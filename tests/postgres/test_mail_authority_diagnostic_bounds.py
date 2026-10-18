import ast, pathlib, types, unittest
class Bounds(unittest.TestCase):
 def test_versioned_deadlines_and_historical_limits(self):
  tree=ast.parse(pathlib.Path(__file__).with_name('run-mail-judge-calibration.py').read_text())
  assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Tuple) and [v.id for v in n.targets[0].elts]==['parent_seconds','child_seconds','max_http'])
  expression=compile(ast.Expression(assignment.value),'<actual launcher deadline expression>','eval')
  for mode,want in [('authority-v13',(600,540,8)),('authority-v14',(600,540,8)),('authority-v15',(600,540,8)),('baseline',(480,450,6)),('categorical',(840,780,12)),('paired-format',(960,900,14))]:
   self.assertEqual(eval(expression,{'args':types.SimpleNamespace(mode=mode)}),want)
if __name__=='__main__':unittest.main()
