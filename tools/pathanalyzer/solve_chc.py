import sys
import z3

def main():
    # get optional file name
    fname = None
    if len (sys.argv) >= 2:
        fname = sys.argv[1]

    # create a fixedpoint object
    fp = z3.Fixedpoint ()
    fp.set (engine='spacer')

    # optionally disable pre-processing
    # comment this out for faster solving, but less readable output
    fp.set ('fp.xform.slice', False)
    fp.set ('fp.xform.inline_eager', False)
    fp.set ('fp.xform.inline_linear', False)

    query = None
    if fname is not None:
        q = fp.parse_file (fname)
        query = q[0]

    if query is None:
        print( 'Dumping fp, nothing to solve')
        print( fp )
        return

    print ('Solving for query', query)
    res = fp.query (query)

    print (res)
    if res == z3.sat:
        print (fp.get_ground_sat_answer ())
    elif res == z3.unsat:
        print (fp.get_answer ())

if __name__ == '__main__':
    main()
