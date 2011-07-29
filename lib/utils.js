
/**
 * Utility function to merge arrays and return a new copy
 */
exports.merge = function () {
  result = [];
  for (var i=0; i<arguments.length; i++) {
    for (var j=0; j<arguments[i].length; j++) {
      if (!~result.indexOf(arguments[i][j])) {
        result.push(arguments[i][j]);
      }
    }
  }
  return result;
}

/**
 * Utility function to check if a path is matched against a list of templates
 */
exports.match = function (path, paths) {
  for (var i=0; i<paths.length; i++) {
    if ((typeof paths[i] == 'string' && path == paths[i]) || (paths[i] instanceof RegExp && paths[i].test(path))) return true;
  }
  return false;
}
