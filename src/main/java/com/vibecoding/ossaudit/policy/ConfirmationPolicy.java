package com.vibecoding.ossaudit.policy;

public final class ConfirmationPolicy {

    private ConfirmationPolicy() {
    }

    public static void requireSensitiveExportConfirmation(boolean includeSensitive, boolean confirmed) {
        if (includeSensitive && !confirmed) {
            throw new IllegalArgumentException("Sensitive details require --confirm-sensitive-export.");
        }
    }

    public static void requireExternalShareConfirmation(boolean confirmed) {
        if (!confirmed) {
            throw new IllegalArgumentException("External sharing helpers require --confirm-external-share.");
        }
    }
}
