<p>Changes/Info:</p>
<p>4/1/2014 - April Fools!<br />
For a complete explanation as to how I traversed the VBN file to make this script work: http://dofir.net/post/81425257003/a-study-of-symantecs-vbn-file-format - Team Dofir FTW! :)</p>
<p>Issues:</p>
<p>7/28/2014:
Got a syntax error on line 73 due to not enough parameters being passed to the function "dataread".<br />
This is due to the fact that not all VBN files contain the file that was quarantined.<br />
There is a check in the script that looks for the VBN file size being smaller than the quarantined<br />
file size (which is obviously impossible) but this particulr VBN file eluded that check.<br />
Still a work in progress. :)<p>