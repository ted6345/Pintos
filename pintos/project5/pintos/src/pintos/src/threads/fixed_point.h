#define F (1 << 14)
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

int int_to_fp(int n);
int fp_to_int_round(int x);
int fp_to_int(int x);
int add_fp(int x, int y);
int add_mixed(int x, int n);
int sub_fp(int x, int y);
int sub_mixed(int x, int n);
int mult_fp(int x, int y);
int mult_mixed(int x, int n);
int div_fp(int x, int y);
int div_mixed(int x, int n);

/*Convert integer n to fixed-point number*/
int int_to_fp(int n){
	return n * F;
}

/*Convert fixed-point number x to integer(round down)*/
int fp_to_int(int x){
	return x / F;
}

/*Convert fixed-point number x to integer(round off)*/
int fp_to_int_round(int x){
	if(x >= 0)
		return (x + F/2)/F;
	else
		return (x - F/2)/F;
}

/*Addition between fixed-point numbers*/
int add_fp(int x, int y){
	return x + y;
}

/*Addition between fixed-point number and integer*/
int add_mixed(int x, int n){
	return x + n*F;
}

/*Subtraction between fixed-point numbers*/
int sub_fp(int x, int y){
	return x - y;
}

/*Subtraction between fixed-point number and integer*/
int sub_mixed(int x, int n){
	return x - n*F;
}

/*Multiplication between fixed-point numbers*/
int mult_fp(int x, int y){
	return ((int64_t)x)*y/F;
}

/*Multiplication between fixed-point number and integer*/
int mult_mixed(int x, int n){
	return x*n;
}

/*Division between fixed-point numbers*/
int div_fp(int x, int y){
	return ((int64_t)x)*F/y;
}

/*Division between fixed-point number and integer*/
int div_mixed(int x, int n){
	return x/n;
}
