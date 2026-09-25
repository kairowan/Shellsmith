package dev.mocika.shield.loader;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

public class MocikaPlayDeliveryTest {
    @Test
    public void encryptedPathIsPackScopedAndNormalized() {
        assertEquals(
                "voice_pack/protector/aenc/voice/sample.bin",
                MocikaPlayDelivery.encryptedRelativePath(
                        "voice_pack", "assets/voice\\sample.bin"));
    }

    @Test
    public void traversalAndInvalidPackNamesAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> MocikaPlayDelivery.encryptedRelativePath("bad-pack", "voice.bin"));
        assertThrows(IllegalArgumentException.class,
                () -> MocikaPlayDelivery.encryptedRelativePath("voice_pack", "../voice.bin"));
    }
}
