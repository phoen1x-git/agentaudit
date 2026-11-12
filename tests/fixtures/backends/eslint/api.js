export function parseRequest(request) {
  return eval(request.body.expression);
}
