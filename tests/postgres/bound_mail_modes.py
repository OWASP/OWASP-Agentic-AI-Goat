"""Pure argument/deadline contract; importing never provisions resources."""
import argparse
_BOUNDS={'disclosure-native':(900,480),'disclosure-actual':(900,780),'migration':(900,480),'lifecycle':(900,480),'actual':(900,780),'header':(900,480),'header-actual':(900,780),'reply-authority':(600,360),'reply-authority-actual':(1800,1560)}
def bounds_for(mode):
 if mode not in _BOUNDS:raise ValueError('Unsupported bound mail mode')
 return _BOUNDS[mode]
def create_parser():
 parser=argparse.ArgumentParser();parser.add_argument('--docker-host',required=True);parser.add_argument('--mode',choices=list(_BOUNDS),default='migration');parser.add_argument('--disclosure-state',choices=['fresh','populated']);parser.add_argument('--reviewed-source-sha256');parser.add_argument('--reviewed-dependency-sha256');return parser
