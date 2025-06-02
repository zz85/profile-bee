
// just a busy loop
void hot(void) {
    for(;;) {}
}

void function_c(void) {
    hot();
}


void function_b(void) {
    function_c();
}


void function_a(void) {
    function_b();
}

// just a simple C program that call functions 3 layer deep
void main(void) {
    function_a();
}

