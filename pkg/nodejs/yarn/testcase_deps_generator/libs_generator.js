const fs = require("fs");
const yarnpkg = require("@yarnpkg/lockfile");
const YAML = require("yaml");
const { Console } = require("console");

let fileContent = "";
const ignoredProtocols = [
  "workspace",
  "patch",
  "file",
  "link",
  "portal",
  "github",
];

const formatYarnV2 = (yaml) => {
  delete yaml.__metadata;
  delete yaml["code@workspace:."];

  result = {};
  for (const [key, value] of Object.entries(yaml)) {
    for (const splitKey of key.split(", ")) {
      result[splitKey] = value;
    }
  }

  for (const [key, value] of Object.entries(result)) {
    if (key.includes("@npm:")) {
      result[key.replace("@npm:", "@")] = value;
      delete result[key];
    }
  }

  return result;
};

const formatYarnV1 = (obj) => obj.object;

const readLockFile = (filepath) => {
  fileContent = fs.readFileSync(filepath, "utf8");

  try {
    return formatYarnV1(yarnpkg.parse(fileContent));
  } catch (e) {
    return formatYarnV2(YAML.parse(fileContent));
  }
};

const setLocations = (value) => {
  const startIndex = fileContent.split("\n").findIndex((line, i) => {
    const isName =
      !ignoredProtocols.find((d) => line.includes(`@${d}`)) &&
      (line.startsWith(`${value.name}@`) || line.startsWith(`"${value.name}@`));
    let isVersion = false;
    if (isName) {
      isVersion = fileContent.split("\n")[i + 1].includes(` ${value.version}`);
    }

    return isName && isVersion;
  });
  let endIndex = fileContent
    .split("\n")
    .slice(startIndex)
    .findIndex((line) => line.trim() === "");

  endIndex =
    endIndex === -1 ? fileContent.split("\n").length : endIndex + startIndex;
  return [startIndex + 1, endIndex];
};

const createResultObj = (yarnObj) => {
  result = {};

  for (const [key, value] of Object.entries(yarnObj)) {
    if (!ignoredProtocols.find((d) => key.includes(`@${d}`))) {
      const dep = key.split(",")[0];
      const i = dep.lastIndexOf("@");
      const name = dep.slice(0, i);

      libId = `${name}@${value.version}`;

      if (!result[libId]) {
        result[libId] = { indirect: false };
      }
      result[libId].name = name;
      result[libId].version = value.version;
      result[libId].suffix = result[libId].suffix
        ? `${result[libId].suffix}, ${key}`
        : key;

      result[libId].dependencies = value.dependencies ? value.dependencies : {};
    }
  }

  //console.log(Object.entries(result).filter(([a,d]) => a.includes("parse5") || d.suffix.includes("parse5") ));

  for (const [key, value] of Object.entries(result)) {
    for (const [name, version] of Object.entries(value.dependencies)) {
      let foundChild = Object.keys(result).find(
        (d) =>
          d === `${name}@${version}` ||
          (result[d].suffix.includes(`${name}@${version}`) &&
            result[d].name === name)
      );
      if (foundChild) {
        result[foundChild].indirect = true;
      }
    }

    value.locations = setLocations(value);
  }

  return result;
};

const createResultString = (result) => {
  res = "[]types.Library{\n";
  for (const [key, value] of Object.entries(result)) {
    res += '{ID:"' + key + '",';
    res += `Name:"${value.name}", Version: "${value.version}", Indirect: ${value.indirect}, Locations:[]types.Location{{StartLine: ${value.locations[0]}, EndLine: ${value.locations[1]}}}}, \n`;
  }
  res += "}";
  return res;
};

var args = process.argv.slice(2);
filePath = args[0];

lockfile = readLockFile(filePath);
resultObj = createResultObj(lockfile);
resultString = createResultString(resultObj);

console.log(resultString);
