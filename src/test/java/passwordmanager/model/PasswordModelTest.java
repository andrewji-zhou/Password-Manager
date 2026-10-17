package passwordmanager.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordModelTest {
    private File file;

    @BeforeEach
    void setUp(@TempDir File dir) {
        file = new File(dir, "passwords.txt");
        PasswordModel.useFile(file);
    }

    @Test
    void newFileUnlocksWithTheSamePassword() throws Exception {
        assertFalse(PasswordModel.passwordFileExists());
        PasswordModel.initializePasswordFile("master");
        assertTrue(PasswordModel.passwordFileExists());
        assertTrue(PasswordModel.verifyPassword("master"));
    }

    @Test
    void wrongMasterPasswordIsRejected() throws Exception {
        PasswordModel.initializePasswordFile("master");
        assertFalse(PasswordModel.verifyPassword("nope"));
    }

    @Test
    void entriesPersistAcrossSessions() throws Exception {
        PasswordModel.initializePasswordFile("master");
        PasswordModel model = new PasswordModel();
        model.addPassword(new Password("Steam", "p@ss"));
        model.addPassword(new Password("Email", "other"));

        assertTrue(PasswordModel.verifyPassword("master"));
        PasswordModel reloaded = new PasswordModel();
        assertEquals(2, reloaded.getPasswords().size());
        assertEquals("Steam", reloaded.getPasswords().get(0).getLabel());
        assertEquals("p@ss", reloaded.getPasswords().get(0).getPassword());
    }

    @Test
    void updateAndDeleteArePersisted() throws Exception {
        PasswordModel.initializePasswordFile("master");
        PasswordModel model = new PasswordModel();
        model.addPassword(new Password("A", "1"));
        model.addPassword(new Password("B", "2"));
        model.updatePassword(new Password("A", "changed"), 0);
        model.deletePassword(1);

        PasswordModel.verifyPassword("master");
        PasswordModel reloaded = new PasswordModel();
        assertEquals(1, reloaded.getPasswords().size());
        assertEquals("changed", reloaded.getPasswords().get(0).getPassword());
    }

    @Test
    void passwordsAreNotStoredInPlaintext() throws Exception {
        PasswordModel.initializePasswordFile("master");
        new PasswordModel().addPassword(new Password("Bank", "super-secret-value"));
        assertFalse(Files.readString(file.toPath()).contains("super-secret-value"));
    }

    @Test
    void labelsAreNotStoredInPlaintext() throws Exception {
        PasswordModel.initializePasswordFile("master");
        new PasswordModel().addPassword(new Password("MyBankLabel", "pw"));
        assertFalse(Files.readString(file.toPath()).contains("MyBankLabel"));
    }

    @Test
    void encryptThenDecryptRoundTrips() throws Exception {
        byte[] key = PasswordModel.generateKey("master", new byte[16]);
        assertEquals("hunter2 ✓", PasswordModel.decryptPassword(key, PasswordModel.encryptPassword(key, "hunter2 ✓")));
    }

    @Test
    void samePlaintextEncryptsDifferentlyEachTime() throws Exception {
        byte[] key = PasswordModel.generateKey("master", new byte[16]);
        assertNotEquals(PasswordModel.encryptPassword(key, "same"), PasswordModel.encryptPassword(key, "same"));
    }

    @Test
    void tamperedCiphertextIsRejected() throws Exception {
        byte[] key = PasswordModel.generateKey("master", new byte[16]);
        byte[] data = Base64.getDecoder().decode(PasswordModel.encryptPassword(key, "secret"));
        data[data.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(data);
        assertThrows(GeneralSecurityException.class, () -> PasswordModel.decryptPassword(key, tampered));
    }
}
