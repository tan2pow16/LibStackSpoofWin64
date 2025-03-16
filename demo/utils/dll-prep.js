'use strict';

'use strict';

const fs = require('fs');

/*
 * Copyright (c) 2025, tan2pow16.
 *  All rights reserved.
 */

function __main__(args)
{
  if(args.length !== 2)
  {
    console.log('Usage: node dll-prep.js <path/to/input.S> <path/to/output.S>');
    return;
  }

  let lines = fs.readFileSync(args[0]).toString('ascii');

  lines = lines.replace(/__wchar_main__/g, "Py_Main");
  lines += ' .section .drectve\n .ascii " -export:\\"Py_Main\\""\n';

  fs.writeFileSync(args[1], lines);
}

if(require.main === module)
{
  __main__(process.argv.slice(2));
}
