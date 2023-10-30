#[cfg(test)]
mod tests {
    use secp::Point;

    #[test]
    fn test_sort_public_keys() {
        const KEY_SORT_VECTORS: &[u8] = include_bytes!("test_vectors/key_sort_vectors.json");

        #[derive(serde::Deserialize)]
        struct KeySortVectors {
            pubkeys: Vec<Point>,
            sorted_pubkeys: Vec<Point>,
        }

        let vectors: KeySortVectors = serde_json::from_slice(KEY_SORT_VECTORS)
            .expect("failed to decode key_sort_vectors.json");

        let mut pubkeys = vectors.pubkeys;
        pubkeys.sort();
        assert_eq!(pubkeys, vectors.sorted_pubkeys);
    }
}
