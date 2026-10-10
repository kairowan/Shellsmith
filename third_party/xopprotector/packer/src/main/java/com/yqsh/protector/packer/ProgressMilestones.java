package com.yqsh.protector.packer;

/**
 * Sparse progress lines for long file loops (every 10%) so Desktop/stdout
 * stay responsive without per-file spam.
 */
final class ProgressMilestones {
    private final String label;
    private final int total;
    private int done;
    private int nextPct = 10;

    ProgressMilestones(String label, int total) {
        this.label = label;
        this.total = Math.max(0, total);
        if (this.total > 0) {
            System.out.println(label + ": 0/" + this.total + " (0%)");
        }
    }

    void tick() {
        done++;
        if (total <= 0) {
            return;
        }
        int pct = done >= total ? 100 : (int) (done * 100L / total);
        while (nextPct <= pct && nextPct <= 100) {
            System.out.println(label + ": " + done + "/" + total + " (" + nextPct + "%)");
            nextPct += 10;
        }
    }

    /** Ensure a final 100% line if the last tick did not land exactly on a milestone. */
    void finish() {
        if (total <= 0 || nextPct > 100) {
            return;
        }
        System.out.println(label + ": " + done + "/" + total + " (100%)");
        nextPct = 110;
    }
}
