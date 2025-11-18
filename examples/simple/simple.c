// compile using
// gcc -nostdlib  simple.c -o simple.bin

static int FIB_TABLE[8] = {1, 1, 2, 3, 5, 8, 13, 21};

int _start()
{
    return FIB_TABLE[1];
}
