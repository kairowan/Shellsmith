package dev.mocika.shield.loader;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/** Restores TheRouter's sourceDir-based fallback registry for encrypted in-memory DEX. */
final class TheRouterCompat {
    private static final String TAG = "trc";
    private static final String INDEX_ASSET = "therouter_registry.txt";
    private static final String AUTOWIRED_SUFFIX = "__TheRouter__Autowired";

    private TheRouterCompat() {}

    static void prepare(Context context) {
        try {
            Registry registry = readRegistry(context);
            if (registry.holder == null || registry.isEmpty()) return;

            ClassLoader loader = context.getClassLoader();
            Class<?> holder = Class.forName(registry.holder, false, loader);
            Collection<Object> services = collection(holder, "getServiceProviderIndex");
            Collection<Object> routes = collection(holder, "getRouterMapIndex");
            Map<Class<?>, Method> autowired = map(holder, "getAutowiredIndex");

            addInstances(loader, registry.services, services);
            addInstances(loader, registry.routes, routes);
            addAutowired(loader, registry.autowired, autowired);
        } catch (FileNotFoundException ignored) {
            // Host does not use TheRouter's runtime-scanning fallback.
        } catch (Exception e) {
            // Compatibility adapters must never stop an otherwise runnable host.
            Log.e(TAG, "T01", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Collection<Object> collection(Class<?> holder, String methodName)
            throws Exception {
        Method method = holder.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return (Collection<Object>) method.invoke(null);
    }

    @SuppressWarnings("unchecked")
    private static Map<Class<?>, Method> map(Class<?> holder, String methodName)
            throws Exception {
        Method method = holder.getDeclaredMethod(methodName);
        method.setAccessible(true);
        return (Map<Class<?>, Method>) method.invoke(null);
    }

    private static void addInstances(
            ClassLoader loader, List<String> names, Collection<Object> target) {
        for (String name : names) {
            try {
                Class<?> type = Class.forName(name, false, loader);
                if (!containsClass(target, type)) {
                    target.add(type.getDeclaredConstructor().newInstance());
                }
            } catch (Exception e) {
                Log.w(TAG, "T02", e);
            }
        }
    }

    private static boolean containsClass(Collection<Object> values, Class<?> type) {
        for (Object value : values) {
            if (value != null && value.getClass() == type) return true;
        }
        return false;
    }

    private static void addAutowired(
            ClassLoader loader, List<String> names, Map<Class<?>, Method> target) {
        for (String name : names) {
            try {
                Class<?> generated = Class.forName(name, false, loader);
                Class<?> host = Class.forName(
                        name.substring(0, name.length() - AUTOWIRED_SUFFIX.length()),
                        false,
                        loader);
                Method injector = findAutowiredMethod(generated);
                injector.setAccessible(true);
                target.put(host, injector);
            } catch (Exception e) {
                Log.w(TAG, "T03", e);
            }
        }
    }

    static Method findAutowiredMethod(Class<?> type) throws NoSuchMethodException {
        for (Method method : type.getDeclaredMethods()) {
            Class<?>[] parameters = method.getParameterTypes();
            if (Modifier.isStatic(method.getModifiers())
                    && method.getReturnType() == void.class
                    && parameters.length == 1
                    && parameters[0] == Object.class) {
                return method;
            }
        }
        throw new NoSuchMethodException("T04");
    }

    private static Registry readRegistry(Context context) throws Exception {
        Registry result = new Registry();
        try (InputStream input = context.getAssets().open(INDEX_ASSET);
             BufferedReader reader = new BufferedReader(new InputStreamReader(input, "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                int separator = line.indexOf('\t');
                if (separator <= 0 || separator == line.length() - 1) continue;
                String kind = line.substring(0, separator);
                String name = line.substring(separator + 1).trim();
                if (name.isEmpty()) continue;
                if ("HOLDER".equals(kind)) result.holder = name;
                else if ("SERVICE".equals(kind)) result.services.add(name);
                else if ("ROUTE".equals(kind)) result.routes.add(name);
                else if ("AUTOWIRED".equals(kind)) result.autowired.add(name);
            }
        }
        return result;
    }

    private static final class Registry {
        String holder;
        final List<String> services = new ArrayList<>();
        final List<String> routes = new ArrayList<>();
        final List<String> autowired = new ArrayList<>();

        boolean isEmpty() {
            return services.isEmpty() && routes.isEmpty() && autowired.isEmpty();
        }
    }
}
