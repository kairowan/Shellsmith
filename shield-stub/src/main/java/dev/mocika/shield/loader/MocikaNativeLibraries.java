package dev.mocika.shield.loader;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Materializes selected encrypted business SOs before application classes can load them. */
final class MocikaNativeLibraries {
    private static final String KEY_TABLE = "protector/mocika-sokeys.bin";
    private static final int MAX_TABLE = 1024 * 1024;
    private static final int MAX_SO = 32 * 1024 * 1024;
    private static volatile File preparedDirectory;
    private static String preparedAbi;
    private static final Set<String> preparedNames = new LinkedHashSet<>();

    private MocikaNativeLibraries() {}

    static synchronized void install(Context context, ClassLoader loader) throws Exception {
        File directory = prepare(context);
        if (directory == null) return;
        prependNativeDirectory(loader, directory);
    }

    static synchronized File prepare(Context context) throws Exception {
        byte[] table = readOptionalAsset(context, KEY_TABLE, MAX_TABLE);
        if (table == null) return null;
        String[] names = Ld.w(table);
        if (names == null || names.length == 0) throw new SecurityException("N51");

        ApplicationInfo info = context.getApplicationInfo();
        String abi = findAbi(info, names);
        if (abi == null) {
            // The APK may contain protected libraries for a different ABI only.
            return preparedDirectory;
        }
        if (preparedAbi != null && !preparedAbi.equals(abi)) {
            throw new SecurityException("N65");
        }
        File root = new File(context.getDir("mocika_native", Context.MODE_PRIVATE),
                "mn-" + getVersionCode(context) + "-" + abi);
        if (!root.isDirectory() && !root.mkdirs()) throw new SecurityException("N52");
        int written = 0;
        for (String name : names) {
            if (preparedNames.contains(name)) continue;
            byte[] encrypted = readLibrary(info, abi, name);
            if (encrypted == null) continue;
            byte[] plain = Ld.x(name, encrypted);
            if (plain == null || plain.length == 0) throw new SecurityException("N53");
            writeAtomically(root, name, plain);
            preparedNames.add(name);
            written++;
        }
        if (written == 0 && preparedDirectory == null) return null;
        preparedAbi = abi;
        preparedDirectory = root;
        return root;
    }

    static String searchPath(Context context) {
        Set<String> paths = new LinkedHashSet<>();
        File protectedRoot = preparedDirectory;
        if (protectedRoot != null) paths.add(protectedRoot.getAbsolutePath());
        ApplicationInfo info = context.getApplicationInfo();
        if (info.nativeLibraryDir != null && !info.nativeLibraryDir.isEmpty()) {
            paths.add(info.nativeLibraryDir);
        }
        for (String archive : apkPaths(info)) {
            for (String abi : Build.SUPPORTED_ABIS) {
                if (abi != null && !abi.isEmpty()) paths.add(archive + "!/lib/" + abi);
            }
        }
        StringBuilder value = new StringBuilder();
        for (String path : paths) {
            if (value.length() > 0) value.append(File.pathSeparatorChar);
            value.append(path);
        }
        return value.toString();
    }

    private static String findAbi(ApplicationInfo info, String[] names) throws Exception {
        List<String> archives = apkPaths(info);
        for (String abi : Build.SUPPORTED_ABIS) {
            if (abi == null || abi.isEmpty()) continue;
            for (String name : names) {
                File extracted = info.nativeLibraryDir == null
                        ? null : new File(info.nativeLibraryDir, name);
                if (extracted != null && extracted.isFile()) return abi;
                for (String archive : archives) {
                    try (ZipFile zip = new ZipFile(archive)) {
                        if (zip.getEntry("lib/" + abi + "/" + name) != null) {
                            return abi;
                        }
                    }
                }
            }
        }
        return null;
    }

    private static byte[] readLibrary(ApplicationInfo info, String abi, String name)
            throws Exception {
        if (info.nativeLibraryDir != null) {
            File extracted = new File(info.nativeLibraryDir, name);
            if (extracted.isFile()) {
                if (extracted.length() > MAX_SO) throw new SecurityException("N63");
                try (InputStream input = new FileInputStream(extracted)) {
                    return readBounded(input, MAX_SO);
                }
            }
        }
        for (String archive : apkPaths(info)) {
            try (ZipFile zip = new ZipFile(archive)) {
                ZipEntry entry = zip.getEntry("lib/" + abi + "/" + name);
                if (entry == null) continue;
                if (entry.getSize() > MAX_SO) throw new SecurityException("N64");
                try (InputStream input = zip.getInputStream(entry)) {
                    return readBounded(input, MAX_SO);
                }
            }
        }
        return null;
    }

    private static List<String> apkPaths(ApplicationInfo info) {
        Set<String> paths = new LinkedHashSet<>();
        if (info.sourceDir != null && !info.sourceDir.isEmpty()) paths.add(info.sourceDir);
        if (Build.VERSION.SDK_INT >= 21 && info.splitSourceDirs != null) {
            for (String split : info.splitSourceDirs) {
                if (split != null && !split.isEmpty()) paths.add(split);
            }
        }
        return new ArrayList<>(paths);
    }

    private static void prependNativeDirectory(ClassLoader loader, File directory)
            throws Exception {
        Object pathList = findField(loader.getClass(), "pathList").get(loader);
        Field nativeDirectories = findField(pathList.getClass(), "nativeLibraryDirectories");
        Object current = nativeDirectories.get(pathList);
        List<File> combined = new ArrayList<>();
        combined.add(directory);
        if (current instanceof List) {
            for (Object item : (List<?>) current) {
                if (item instanceof File && !directory.equals(item)) combined.add((File) item);
            }
            nativeDirectories.set(pathList, combined);
        } else if (current instanceof File[]) {
            File[] old = (File[]) current;
            List<File> unique = new ArrayList<>();
            unique.add(directory);
            for (File file : old) if (!directory.equals(file)) unique.add(file);
            File[] updated = unique.toArray(new File[0]);
            nativeDirectories.set(pathList, updated);
            combined.clear();
            for (File file : updated) combined.add(file);
        } else {
            throw new SecurityException("N55");
        }

        if (Build.VERSION.SDK_INT >= 23) {
            Field elements = findField(pathList.getClass(), "nativeLibraryPathElements");
            List<File> all = new ArrayList<>(combined);
            try {
                Object system = findField(pathList.getClass(), "systemNativeLibraryDirectories")
                        .get(pathList);
                if (system instanceof List) {
                    for (Object item : (List<?>) system) if (item instanceof File) all.add((File) item);
                }
            } catch (NoSuchFieldException ignored) {}
            Method make = findSingleListMethod(pathList.getClass(), "makePathElements");
            Object generated = make.invoke(pathList, all);
            if (generated == null || !generated.getClass().isArray()
                    || Array.getLength(generated) == 0) throw new SecurityException("N56");
            elements.set(pathList, generated);
        }
    }

    private static Method findSingleListMethod(Class<?> type, String name)
            throws NoSuchMethodException {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            for (Method method : current.getDeclaredMethods()) {
                Class<?>[] parameters = method.getParameterTypes();
                if (method.getName().equals(name) && parameters.length == 1
                        && List.class.isAssignableFrom(parameters[0])) {
                    method.setAccessible(true);
                    return method;
                }
            }
        }
        throw new NoSuchMethodException(name);
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                Field field = current.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {}
        }
        throw new NoSuchFieldException(name);
    }

    private static byte[] readOptionalAsset(Context context, String path, int maximum)
            throws Exception {
        InputStream input;
        try {
            input = context.getAssets().open(path);
        } catch (java.io.FileNotFoundException absent) {
            return null;
        }
        try (InputStream stream = input) {
            return readBounded(stream, maximum);
        }
    }

    private static byte[] readBounded(InputStream input, int maximum) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream(8192);
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            output.write(buffer, 0, read);
            if (output.size() > maximum) throw new SecurityException("N57");
        }
        return output.toByteArray();
    }

    private static void writeAtomically(File root, String name, byte[] bytes) throws Exception {
        if (!name.matches("lib[A-Za-z0-9_.+\\-]+\\.so") || bytes.length > MAX_SO) {
            throw new SecurityException("N58");
        }
        File target = new File(root, name);
        if (!target.getCanonicalFile().getParentFile().equals(root.getCanonicalFile())) {
            throw new SecurityException("N59");
        }
        File temporary = new File(root, name + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            output.write(bytes);
            output.flush();
            output.getFD().sync();
        }
        if (!temporary.setReadable(true, true) || !temporary.setExecutable(true, true)) {
            throw new SecurityException("N60");
        }
        if (target.exists() && !target.delete()) throw new SecurityException("N61");
        if (!temporary.renameTo(target)) throw new SecurityException("N62");
    }

    private static long getVersionCode(Context context) throws Exception {
        PackageInfo info = context.getPackageManager().getPackageInfo(context.getPackageName(), 0);
        return Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
    }

}
