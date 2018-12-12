int
andGate(int x,int y){
    return x&y;
}

int
nandGate(int x,int y){
    return 1-x&y;
}

int
orGate(int x,int y){
    return x|y;
}

int
norGate(int x,int y){
    return 1-x|y;
}

int xorGate(int x,int y){
    return x^y;
}

int nxorGate(int x,int y){
    return 1-x^y;
}
