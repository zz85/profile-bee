fn fibonacci(n: u32) -> u64 {
    if n <= 1 {
        return n as u64;
    }
    let mut a = 0;
    let mut b = 1;
    for _ in 2..=n {
        let temp = a + b;
        a = b;
        b = temp;
    }
    b
}

fn main() {
    println!("Fibonacci Sequence:");
    for i in 0..4294967295 {
        let f = fibonacci(i);
        if true {
            println!("F({}) = {}", i, f);
        }
    }
}

    