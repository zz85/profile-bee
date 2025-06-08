use std::collections::HashMap;
use std::thread;
use std::time::Duration;

fn main() {
    let mut number = 2;
    loop {
        if inefficient_is_prime(number) {
            // println!("Found a prime number: {}", number);
            // Unnecessary sleep
            // thread::sleep(Duration::from_millis(100));
        }
        number += 1;
        
        // Unnecessary string manipulation
        let num_str = number.to_string();
        number = num_str.parse::<i32>().unwrap();
        
        if number > 100 {
            number = 2; // Reset to start over
        }
    }
}

fn inefficient_is_prime(n: i32) -> bool {
    if n <= 1 {
        return false;
    }
    
    // Unnecessary use of HashMap
    let mut factors = HashMap::new();
    
    for i in 2..=n {
        if n % i == 0 {
            factors.insert(i, true);
        }
    }
    
    // Unnecessary vector creation and sorting
    let mut factor_vec: Vec<i32> = factors.keys().cloned().collect();
    factor_vec.sort_unstable();
    
    factor_vec.len() == 1
}

