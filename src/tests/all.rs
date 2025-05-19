#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_addition() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn test_basic_subtraction() {
        assert_eq!(5 - 3, 2);
    }

    #[test]
    fn test_basic_multiplication() {
        assert_eq!(3 * 4, 12);
    }

    #[test]
    fn test_basic_division() {
        assert_eq!(10 / 2, 5);
    }

    #[test]
    #[should_panic]
    fn test_divide_by_zero() {
        let _ = 1 / 0;
    }
}
