# ezpass-t
[![Python](https://img.shields.io/badge/python-3.13%2B-blue)](https://www.python.org/)
[![CI](https://github.com/joseph-d-gallant/ezpass-t/actions/workflows/continuous-integration.yml/badge.svg)](https://github.com/joseph-d-gallant/ezpass-t/actions/workflows/continuous-integration.yml)

*A local CLI password manager.*

> **NOTE:** This project has not been reviewed for security nor should it be used without fully understanding the potential associated risks. <br>As a user/dev, you assume and accept the risk when using this application for personal or other-related uses.

## **Overview**

ezpass-t provides a simple terminal workflow for managing credentials without requiring a cloud service.

A user creates an account with a master password, authenticates into a session, and manages entries in an encrypted vault. Passwords can be generated using Python's `secrets` module, encrypted before persistence, and decrypted only when an authenticated session requires access to them.

The project is intentionally structured as a layered application rather than a single CLI script. User interaction, application logic, cryptography, and persistence have separate responsibilities, making the system easier to test and extend.

## **Features**

| Feature | Description |
| --- | --- |
| Account Management | Create accounts, authenticate, logout, and delete accounts |
| Encrypted Vault | Store credentials as encrypted data rather than plaintext |
| Password Generation | Generate passwords using Python's `secrets` module |
| Master-Password Hashing | Store an Argon2 password hash for authentication |
| Key Derivation | Derive the vault encryption key with Scrypt |
| Authenticated Encryption | Protect vault secrets using AES-256-GCM |
| Session Management | Restrict vault operations to authenticated sessions |
| Idle Timeout | Expire inactive sessions automatically |
| Input Validation | Validate registration and credential fields |
| Local Persistence | Store application data in SQLite |
| Repository Authorization | Scope vault operations to the authenticated user |
| Automated Testing | Test cryptography, services, UI behavior, and persistence |

## **Quickstart**

#### Requirements

- Windows OS
- Python 3.13+
- uv

#### Clone the Repository

```bash
git clone <repository-url>
cd ezpass-t
```

#### Install Dependencies

The project uses uv for dependency management and reproducible environments.

```bash
uv sync --group dev
```

#### Configure the Database

Create a `.env` file in the project root:

```bash
DB_FILENAME=ezpass.db
```

The `.env` file is gitignored and is used to configure the local database filename.

#### Run ezpass-t

```bash
uv run ezpass-t
```

On Windows, the SQLite database is stored under:

```text
%LOCALAPPDATA%\ezpass-t\data\
```

If terminal output disappears when the application exits, use debug mode:

```bash
uv run ezpass-t --debug
```

## Documentation
The full documentation can be found [here].
