pub(crate) struct GaloisFieldCalculator {
    exp_table: Vec<u16>,
    log_table: Vec<u16>,
}

#[derive(Debug)]
pub(crate) enum GaloisError {
    DivisionByZero,
    InverseOfZero,
}

impl GaloisFieldCalculator {
    pub(crate) fn new() -> Self {
        let mut exp_table: Vec<u16> = vec![0; 65535];
        let mut log_table: Vec<u16> = vec![0; 65536];

        let mut value: u32 = 1;

        for i in 0..65535 {
            exp_table[i] = value as u16;
            log_table[value as usize] = i as u16;

            value <<= 1;

            if value > 65535 {
                value ^= 0x1100B;
            }
        }

        Self {
            exp_table,
            log_table,
        }
    }

    pub(crate) fn add(&self, a: u16, b: u16) -> u16 {
        a ^ b
    }

    pub(crate) fn divide(&self, lhs: u16, rhs: u16) -> Result<u16, GaloisError> {
        if lhs == 0 {
            return Ok(0);
        }

        if rhs == 0 {
            return Err(GaloisError::DivisionByZero);
        }

        let lhs_exp = self.log_table[lhs as usize];
        let rhs_exp = self.log_table[rhs as usize];

        let mut sum: i32 = lhs_exp as i32 - rhs_exp as i32;

        if sum < 0 {
            sum += 65535;
        }

        Ok(self.exp_table[sum as usize])
    }

    pub(crate) fn inverse(&self, a: u16) -> Result<u16, GaloisError> {
        if a == 0 {
            return Err(GaloisError::InverseOfZero);
        }

        let exp = self.log_table[a as usize];

        let mut value = 65535 - exp;

        if value > 65534 {
            value %= 65535;
        }

        Ok(self.exp_table[value as usize])
    }

    pub(crate) fn multiply(&self, lhs: u16, rhs: u16) -> u16 {
        if lhs == 0 || rhs == 0 {
            return 0;
        }

        let lhs_exp = self.log_table[lhs as usize];
        let rhs_exp = self.log_table[rhs as usize];

        let mut sum: u32 = lhs_exp as u32 + rhs_exp as u32;

        if sum > 65534 {
            sum %= 65535;
        }

        self.exp_table[sum as usize]
    }

    pub(crate) fn power(&self, base: u16, exponent: u16) -> u16 {
        if base == 0 {
            return 0;
        }

        if exponent == 0 {
            return 1;
        }

        let base_exp = self.log_table[base as usize];

        let mut multiplied: u32 = base_exp as u32 * exponent as u32;

        if multiplied > 65534 {
            multiplied %= 65535;
        }

        self.exp_table[multiplied as usize]
    }

    pub(crate) fn subtract(&self, lhs: u16, rhs: u16) -> u16 {
        self.add(lhs, rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_table_unique() {
        let gf = GaloisFieldCalculator::new();
        let unique: std::collections::HashSet<u16> = gf.exp_table.iter().copied().collect();

        assert_eq!(unique.len(), 65535);
        assert!(!unique.contains(&0));
    }

    #[test]
    fn addition_and_subtraction() {
        let gf = GaloisFieldCalculator::new();
        let a = 0x1234;
        let b = 0x5678;

        assert_eq!(gf.add(a, 0), a);
        assert_eq!(gf.subtract(a, 0), a);

        assert_eq!(gf.add(a, a), 0);
        assert_eq!(gf.subtract(a, a), 0);

        assert_eq!(gf.add(a, b), gf.subtract(a, b));

        assert_eq!(gf.add(a, b), gf.add(b, a));
        assert_eq!(gf.subtract(a, b), gf.subtract(b, a));
    }

    #[test]
    fn multiplication() {
        let gf = GaloisFieldCalculator::new();
        let a = 0x1234;
        let b = 0x5678;
        let c = 0x9ABC;

        assert_eq!(gf.multiply(a, 0), 0);
        assert_eq!(gf.multiply(0, a), 0);

        assert_eq!(gf.multiply(a, 1), a);
        assert_eq!(gf.multiply(1, a), a);

        assert_eq!(gf.multiply(a, b), gf.multiply(b, a));

        let ab = gf.multiply(a, b);
        let bc = gf.multiply(b, c);
        assert_eq!(gf.multiply(ab, c), gf.multiply(a, bc));

        let b_plus_c = gf.add(b, c);
        let ab_plus_ac = gf.add(gf.multiply(a, b), gf.multiply(a, c));
        assert_eq!(gf.multiply(a, b_plus_c), ab_plus_ac);
    }

    #[test]
    fn division() {
        let gf = GaloisFieldCalculator::new();
        let a = 0x1234;
        let b = 0x5678;

        assert_eq!(gf.divide(a, 1).unwrap(), a);
        assert_eq!(gf.divide(a, a).unwrap(), 1);
        assert_eq!(gf.divide(0, a).unwrap(), 0);

        assert!(matches!(gf.divide(a, 0), Err(GaloisError::DivisionByZero)));

        let ab = gf.multiply(a, b);
        assert_eq!(gf.divide(ab, b).unwrap(), a);
        assert_eq!(gf.divide(ab, a).unwrap(), b);
    }

    #[test]
    fn inverse() {
        let gf = GaloisFieldCalculator::new();
        let a = 0x1234;

        assert_eq!(gf.inverse(1).unwrap(), 1);

        assert_eq!(gf.multiply(a, gf.inverse(a).unwrap()), 1);

        assert!(matches!(gf.inverse(0), Err(GaloisError::InverseOfZero)));
    }

    #[test]
    fn power() {
        let gf = GaloisFieldCalculator::new();
        let a = 0x1234;

        assert_eq!(gf.power(a, 0), 1);
        assert_eq!(gf.power(a, 1), a);
        assert_eq!(gf.power(a, 2), gf.multiply(a, a));

        let a2 = gf.power(a, 2);
        let a3 = gf.power(a, 3);
        let a5 = gf.power(a, 5);
        assert_eq!(gf.multiply(a2, a3), a5);

        assert_eq!(gf.power(a, 65535), 1);
    }
}
