/**
 * @kind problem
 * @name Function Blocks
 * @id cpp/function-block-location
 * @description Lists functions with their block statement locations.
 */

import cpp
 
from Function f, BlockStmt body
where f.hasDefinition() and
      body = f.getBlock() and
      f.getLocation().getFile() = body.getLocation().getFile()
select f.getName().toString(), body.getLocation().getFile().getAbsolutePath().toString(),
        f.getLocation().getStartLine().toString(),
        body.getLocation().getEndLine().toString()