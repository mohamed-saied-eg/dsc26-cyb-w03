## Tools
- Used AI assistants to help structure the security logic, review Python dataclasses, and format scrypt parameter handling.

## What AI got wrong
- Initial suggestions sometimes missed strict edge cases in Unicode normalisation, parameter boundary checks for scrypt, and exact precedence orders for authorization denial reasons.

## In my own words
1. Why does get_document return 404 rather than 403 when a client asks for another client's contract?
- Returning 404 (Not Found) instead of 403 (Forbidden) prevents attackers from confirming the existence of hidden or restricted documents, protecting against information disclosure and IDOR enumeration.

2. Why must verify_password refuse a stored hash that is shorter than 32 bytes, even though the prefix matches?
- Refusing shorter hashes ensures we never fall back to comparing only a partial prefix of the derived key, which would compromise cryptographic security and allow weak or forged verification matches.
