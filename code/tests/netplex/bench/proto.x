/* $Id$ -*- c -*- */

typedef string longstring<>;
typedef longstring *longstringopt;

program P {
    version V1 {
	void ping(void) = 0;

	int hard_work(void) = 1;
	/* Sleeps one second, the returns "1" */

	void fail(void) = 2;
	/* Simply fails */

	void exit(void) = 3;
	/* Exit with code 3 */

        /* The following is for Netplex_sharedvar, in particular for the
           versioned access method:
        */

        void setvar1(longstring) = 10;
        void setvar2(longstring) = 11;
        longstringopt getvar1(void) = 12;
        longstringopt getvar2(void) = 13;
        void updvar1(void) = 14;
        void updvar2(void) = 15;

    } = 1;
} = 1;
