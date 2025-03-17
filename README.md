# CAD-Image-Protection-Using-Blockchain-Technology

Project Overview:

The CAD Integrity Checker is a security-focused application designed to enhance the protection of CAD drawings against unauthorized modifications. This system leverages blockchain technology and cryptographic algorithms to ensure the integrity of DWG files used in engineering and architectural designs.


Key Features:

Blockchain-Based Security: Ensures that CAD drawings remain tamper-proof by recording their hashes on a decentralized ledger.

Cryptographic Verification: Uses hashing algorithms to generate unique signatures for each DWG file, detecting any unauthorized modifications.

Tamper Prevention Mechanism: Integrates directly within CAD software to monitor and restrict unauthorized edits.

User Authentication & Access Control: Only authorized users can make modifications, ensuring accountability.

Audit Trail: Maintains a secure and verifiable history of file changes.

Integration with CAD Software: Provides seamless usability for engineers and designers.

Technology Stack

Programming Languages: Python

Blockchain Platform: Ethereum (or any lightweight blockchain for recording hashes)

Database: SQLite / PostgreSQL (for metadata storage)

Cryptographic Algorithms: SHA-256 / SHA-3 for hashing

CAD File Handling: DWG file processing with relevant libraries

Frontend: Basic UI for verification and status tracking


Future Enhancements:

Smart Contract Implementation for direct integration with CAD software.

Flutter-based Mobile Application to check file integrity on the go.

Cloud-based Backup for CAD file security.
