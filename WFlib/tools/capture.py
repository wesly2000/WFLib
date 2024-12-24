"""
A module for website browsing and traffic capture. Ideally, they should work coorperatively
in an asynchronized style. The general workflow is as follows.

main        ----------------------------------------------------------------------------------------------------->
                         |      |                                                           ^       ^
browsing                 |      v-----------------------------------------------------------|       |
                         |                                                                          |
capture                  v---------------------------------------------------------------------------
"""