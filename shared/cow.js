function cow(title, message) {
  return [
    ` ${title}`,
    "        \\   ^__^",
    "         \\  (oo)\\_______",
    "            (__)\\       )\\/\\",
    "                ||----w |",
    "                ||     ||",
    ` ${message}`,
  ].join("\n");
}

module.exports = { cow };
