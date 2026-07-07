export function removeChildren(node: Node): void {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

export function text(value: string): Text {
  return document.createTextNode(value);
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: {
    className?: string;
    text?: string;
    type?: string;
    value?: string;
    placeholder?: string;
    title?: string;
    ariaLabel?: string;
    disabled?: boolean;
  } = {},
  children: Array<Node | string> = []
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (options.className) {
    node.className = options.className;
  }
  if (options.text !== undefined) {
    node.textContent = options.text;
  }
  if (options.type && node instanceof HTMLInputElement) {
    node.type = options.type;
  }
  if (options.value !== undefined && (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement)) {
    node.value = options.value;
  }
  if (options.placeholder !== undefined && (node instanceof HTMLInputElement || node instanceof HTMLTextAreaElement)) {
    node.placeholder = options.placeholder;
  }
  if (options.title) {
    node.title = options.title;
  }
  if (options.ariaLabel) {
    node.setAttribute("aria-label", options.ariaLabel);
  }
  if (options.disabled !== undefined) {
    (node as HTMLButtonElement | HTMLInputElement).disabled = options.disabled;
  }
  for (const child of children) {
    node.append(child instanceof Node ? child : text(child));
  }
  return node;
}

export function setDataset(node: HTMLElement, key: string, value: string): void {
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(value)) {
    throw new Error("unsafe dataset value");
  }
  node.dataset[key] = value;
}
