
// just a busy loop
int hot(void) {
    for(;;) {}
}

int function_c(void) {
    hot();
}


int function_b(void) {
    function_c();
}


int function_a(void) {
    function_b();
}

// just a simple C program that call functions 3 layer deep
int main(void) {
    function_a();
}

