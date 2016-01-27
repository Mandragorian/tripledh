#ifdef DEBUG

/*
 * Prints len bytes of data starting a buf, in hexadecimal format
 */
void print_buffer(const unsigned char *buf, size_t len);

/*
 * Prints contents of libgcrypt mpi to_print in hexadecimal format
 */
void print_mpi(gcry_mpi_t to_print);

    #define debug_msg(X) fprintf(stderr,(X))
    #define debug_print_buffer(X,Y) print_buffer((X),(Y))
    #define debug_print_mpi(X) print_mpi((X))
#else

    #define debug_msg(X)
    #define debug_print_buffer(X,Y)
    #define debug_print_mpi(X)

#endif


