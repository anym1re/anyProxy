fn leak(secret: &Secret) -> String {
    secret.expose_hex()
}
