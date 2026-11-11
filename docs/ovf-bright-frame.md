# OVF bright-frame investigation

The X100V optical viewfinder shows a solid bright-line rectangle and separate
corner marks for the parallax-corrected frame. The owner reports that both
are visible continuously.

The stock X100V 3.01 primary partition has a 56-byte layout-record table at
`0x014b83b8`, indexed by a routine at `0x011ab780`. Its variant-1,
layout-4 and layout-5 records for the stock 16:9 aspect are at `0x014b9688`
and `0x014b9810`. The records describe, respectively, a 472×264 window at
`(40,108)` and a 184×102 window at `(520,189)` on a 720×480 plane.

An SD boot experiment changed those record heights to 174 and 67 pixels while
keeping their horizontal positions. The OVF corner marks moved to a 65:24
shape, but the solid rectangle remained 16:9. Focus continued to work.
Therefore these table records affect the corner marks; they do not by
themselves control the solid rectangle.

Static analysis traces the layout-table reader through `0x011ab800`,
`0x011e63a4`, `0x011e6880`, `0x01166c84`, and `0x01153d6c`. The latter's
callers include focus-position routines at `0x0103daa0` and `0x010483c0`.
Those callers clamp focus coordinates and handle movement inputs. They do
not establish the solid bright-line renderer. A search of the decoded
primary image for the record's 472×264 pair found it only in this layout
table, which suggests the solid frame's dimensions are calculated or stored
in another form. This search is limited to that exact pair and image.
The stock strings
`MSG_ITEM_BRIGHTFRAMESET`, `UI_SETP_BRIGHTFRAME`, and `OVF_GUIDE` are
potential search leads only; their names do not establish the shape source.

Next proof requires a distinct code/data read controlling the solid rectangle
and an isolated reversible SD boot test. The table addresses above are
not sufficient to claim that proof.
