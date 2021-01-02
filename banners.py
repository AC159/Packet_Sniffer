from chalky import sty, fg, bg
from random import randint
from pyfiglet import Figlet


def print_banner():

    num = randint(1, 3)

    if num == 1:
        f = Figlet(font='slant')
        print(fg.bright_blue & sty.bold | f.renderText("Rufus!"))

    elif num == 2:
        f = Figlet(font='big')
        print(sty.dim & fg.bright_cyan | f.renderText("Rufus!"))

    elif num == 3:
        f = Figlet(font='starwars')
        print(fg.green & sty.bold | f.renderText("Rufus!"))
