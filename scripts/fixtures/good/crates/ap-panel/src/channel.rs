fn wire(secret: &Secret) -> WireCredential {
    WireCredential::Secret { hex: secret.expose_hex() }
}
