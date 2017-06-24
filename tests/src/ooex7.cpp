#include <iostream>
#include <string>

using namespace std;

class ObjectTest {
private:
  int x,y;
	

public:
  ObjectTest(int a, int b) {x=a; y=b;}
  ObjectTest() {x=0; y = 0;}
  int add() {
    return x+y;
  }

  void print(string msg) {
    for (int c = 0; c < x*y; c++)
      cout << msg << endl;
  }
};


void bar(ObjectTest aa, int bb, int cc, ObjectTest dd) {
  aa.print("bar");
  bb += 1;
}

void foo(int q, ObjectTest e, int c) {
  ObjectTest f(q,c);
  cout << f.add() << endl;
  bar(e,1,3,f);
}

int main() {
  ObjectTest e(9,10);
  foo(4,e,8);
  return 0;
}
/* Local Variables:   */
/* mode: c++          */
/* fill-column:    95 */
/* comment-column: 0  */
/* End:               */
