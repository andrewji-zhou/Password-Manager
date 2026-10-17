# Password Manager

Created September 2025, but now migrating it to GitHub, and polishing up unfinished features.

A desktop password manager written in Java with JavaFX. A single master password unlocks an encrypted vault where you can add, edit, delete and copy credentials. Nothing is stored in plaintext.

Started as a class project (Case Western Reserve University, CSDS 344), then extended with authenticated encryption, encrypted labels and a test suite.

## Features

- Master-password-protected vault, created on first launch
- Add, edit, delete and copy-to-clipboard for entries
- Unit tests covering the crypto and the vault's persistence

## Run it

Requires JDK 21+. The Maven wrapper handles everything else.

```bash
./mvnw javafx:run     # launch the app
./mvnw test           # run the tests
```

The vault is saved as `passwords.txt` in the directory you launch from. It is git-ignored.

## Project layout

```
src/main/java/
├── module-info.java
└── passwordmanager/
    ├── PasswordApplication.java        JavaFX entry point
    ├── InitialController.java          unlock / create-vault screen
    ├── PasswordListController.java     main list + detail screen
    └── model/
        ├── PasswordModel.java          key derivation, AES-GCM, vault file I/O
        └── Password.java               label + password
src/main/resources/passwordmanager/     FXML views (initial-view, passwordlist-view)
src/test/java/passwordmanager/model/    JUnit 5 tests
```

## Limitations

This is a learning project, not a replacement for a vetted password manager.

- The number of entries and the length of each label and password are visible in the file.
- Decrypted passwords stay in memory (as Java `String`s) while the app is open, and the clipboard is not auto-cleared.
- There is no master-password change, lock timeout, or password generator.
- The vault format is not versioned.
