-- include.lua replaces a code block marked {include="path"} with the
-- content of the file at path (relative to the repository root), so that
-- the documents show the tested samples rather than copies of them:
--
--     ```{.yaml include="examples/signer.yaml"}
--     ```
--
-- With keys="a b", only those top-level YAML keys are shown, each with
-- everything indented below it, in file order:
--
--     ```{.yaml include="docs/planning-guide/examples/x.yaml" keys="realms governance"}
--     ```
--
-- A missing file, or a key not in the file, fails the build.

-- only keeps the top-level blocks of text whose key is in keys.
local function only(text, keys)
  local want, seen, out, keep = {}, {}, {}, false
  for k in keys:gmatch("%S+") do want[k] = true end
  for line in (text .. "\n"):gmatch("(.-)\n") do
    local key = line:match("^([%w_]+):")
    if key then keep = want[key] or false; if keep then seen[key] = true end
    elseif line:match("^%S") then keep = false end
    if keep then table.insert(out, line) end
  end
  for k in pairs(want) do
    if not seen[k] then error("include: no top-level key " .. k) end
  end
  return (table.concat(out, "\n"):gsub("%s+$", ""))
end

function CodeBlock(block)
  local path = block.attributes.include
  if not path then
    return nil
  end
  local file = io.open(path, "r")
  if not file then
    error("include: cannot read " .. path)
  end
  block.text = file:read("a"):gsub("\n$", "")
  file:close()
  if block.attributes.keys then
    block.text = only(block.text, block.attributes.keys)
    block.attributes.keys = nil
  end
  block.attributes.include = nil
  return block
end
