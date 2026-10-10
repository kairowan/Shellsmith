package com.yqsh.protector.packer;

import pxb.android.axml.AxmlParser;

import java.io.IOException;
import java.nio.file.Files;
import java.io.File;

final class ManifestHelperLocal {
    private ManifestHelperLocal() {}

    static String getApplicationName(File manifest) {
        try {
            byte[] data = Files.readAllBytes(manifest.toPath());
            AxmlParser parser = new AxmlParser(data);
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) continue;
                if (!"application".equals(parser.getName())) continue;
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if ("name".equals(parser.getAttrName(i))) {
                        Object v = parser.getAttrValue(i);
                        return v == null ? null : String.valueOf(v);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /** Manifest {@code package} / applicationId (e.g. {@code com.foo.bar}). */
    static String getPackageName(File manifest) {
        try {
            byte[] data = Files.readAllBytes(manifest.toPath());
            AxmlParser parser = new AxmlParser(data);
            while (parser.next() != AxmlParser.END_FILE) {
                if (parser.getAttrCount() == 0) continue;
                if (!"manifest".equals(parser.getName())) continue;
                for (int i = 0; i < parser.getAttrCount(); i++) {
                    if ("package".equals(parser.getAttrName(i))) {
                        Object v = parser.getAttrValue(i);
                        return v == null ? null : String.valueOf(v);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
