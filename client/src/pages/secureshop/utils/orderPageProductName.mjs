const encoder = new TextEncoder();

export const validOrderPageProductName = value => typeof value === 'string'
  && value.trim() === value && value.length > 0 && value.isWellFormed()
  && !value.includes('\0') && encoder.encode(value).byteLength <= 128;
