@0xd3bf4a73e8848c46;

struct Call {
    id @0 :UInt64;
    union {
        route @1 :Data;
        payload @2 :Data;
    }
}