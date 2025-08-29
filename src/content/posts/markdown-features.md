---
title: "Complete Guide to Markdown Features"
date: 2024-01-25
description: "Explore all the markdown features available in this Obsidian-inspired blog theme, including callouts, code blocks, tables, and advanced formatting options."
image: "https://pixabay.com/get/g2458558f774cf75fc718afb49ac5a3116d6d86f3349f7cf227f1678b580ccfb718edd582befe99cf573cd63bfaef970a800c45808519bdc7c8af5b64ae86b3b1_1280.jpg"
imageAlt: "Code editor with markdown syntax highlighting"
imageOG: true
tags:
- markdown
- formatting
- tutorial
- reference
targetKeyword: "markdown features"
---
This post demonstrates all the markdown features available in our Obsidian-inspired blog theme. Use this as both a reference guide and a showcase of what's possible with our enhanced markdown processing.

## Basic Formatting

### Text Emphasis

- **Bold text** using `**bold**` or `__bold__`
- *Italic text* using `*italic*` or `_italic_`
- ***Bold and italic*** using `***text***`
- ~~Strikethrough~~ using `~~text~~`
- ==Highlighted text== using `==text==`
- `Inline code` using backticks

### Headings

# Heading 1
## Heading 2
### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6

```markdown
# Heading 1
## Heading 2
### Heading 3
#### Heading 4
##### Heading 5
###### Heading 6
```

## Callouts and Admonitions

Our theme supports Obsidian-style callouts with proper icons and styling. Each callout type has its own color scheme and matching Lucide icon.

### Basic Callouts

> [!note] Note
> This is a note callout. Use it for general information that readers should be aware of.

> [!tip] Tip
> This is a tip callout. Perfect for helpful suggestions and best practices.

> [!important] Important
> This is an important callout. Use it to highlight critical information.

> [!warning] Warning
> This is a warning callout. Use it to alert readers about potential issues.

> [!caution] Caution
> This is a caution callout. Use it for dangerous or risky situations.

### Custom Titles

> [!note] Custom Note Title
> You can customize the title of any callout by adding text after the callout type.

> [!tip] Pro Tip
> Custom titles help you provide more context for your callouts.

### Extended Callout Types

> [!info] Info
> Info callouts provide additional context or details.

> [!success] Success
> Success callouts highlight positive outcomes or achievements.

> [!question] Question
> Question callouts can be used to pose questions or highlight areas of uncertainty.

> [!example] Example
> Example callouts are perfect for showcasing code examples or demonstrations.

> [!quote] Quote
> Quote callouts can be used to highlight important quotes or references.

## Multiple Image Layouts

Our theme automatically arranges consecutive images in responsive grid layouts based on the number of images. Images can be placed together without empty lines between them to create these layouts.

### Two Images Side by Side

![Mountain landscape](https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=800&h=600&fit=crop)
![Ocean view](https://images.unsplash.com/photo-1439066615861-d1af74d74000?w=800&h=600&fit=crop)

### Three Images in a Row

![Forest path](https://images.unsplash.com/photo-1441974231531-c6227db76b6e?w=800&h=600&fit=crop)
![Desert sunset](https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=800&h=600&fit=crop)
![City skyline](https://images.unsplash.com/photo-1449824913935-59a10b8d2000?w=800&h=600&fit=crop)

### Four Images in a 2x2 Grid

![Winter landscape](https://images.unsplash.com/photo-1547036967-23d11aacaee0?w=800&h=600&fit=crop)
![Spring flowers](https://images.unsplash.com/photo-1490750967868-88aa4486c946?w=800&h=600&fit=crop)
![Summer beach](https://images.unsplash.com/photo-1507525428034-b723cf961d3e?w=800&h=600&fit=crop)
![Autumn leaves](https://images.unsplash.com/photo-1441260038675-7329ab4cc264?w=800&h=600&fit=crop)

### How to Use

Simply place multiple images together without empty lines between them:

```markdown
![Image 1](image1.jpg)
![Image 2](image2.jpg)
![Image 3](image3.jpg)
```

The layout automatically adapts:
- **2 images**: Side by side
- **3 images**: Three columns 
- **4 images**: 2x2 grid
- **5 images**: 3+2 layout
- **6 images**: 3x2 grid

On mobile devices, all layouts switch to a single column for better readability.

## Lists

### Unordered Lists

- First item
- Second item
  - Nested item
  - Another nested item
    - Deeply nested item
- Third item

### Ordered Lists

1. First step
2. Second step
   1. Sub-step A
   2. Sub-step B
      1. Sub-sub-step
3. Third step

### Task Lists

- [x] Completed task
- [ ] Incomplete task
- [x] Another completed task
  - [ ] Nested incomplete task
  - [x] Nested completed task
- [ ] Final incomplete task

## Links and References

### Basic Links

[Visit our homepage](/) or check out [external links](https://obsidian.md).

### Wikilinks

You can create internal links using double brackets: [[Getting Started]] or [[Markdown Features]].

### Reference Links

This is a [reference link][1] and this is another [reference link][markdown].

[1]: https://example.com
[markdown]: https://daringfireball.net/projects/markdown/

## Code Blocks

### Inline Code

Use `const variable = 'value'` for inline code snippets.

### JavaScript

```javascript
function greetUser(name) {
  console.log(`Hello, ${name}!`);
  return `Welcome to our blog, ${name}`;
}

const user = "Developer";
greetUser(user);
```

### Python

```python
def calculate_fibonacci(n):
    """Calculate the nth Fibonacci number."""
    if n <= 1:
        return n
    return calculate_fibonacci(n-1) + calculate_fibonacci(n-2)

# Example usage
for i in range(10):
    print(f"F({i}) = {calculate_fibonacci(i)}")
```

### CSS

```css
.button {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  border: none;
  border-radius: 8px;
  color: white;
  padding: 12px 24px;
  transition: transform 0.2s ease;
}

.button:hover {
  transform: translateY(-2px);
}
```

### Bash/Shell

```bash
#!/bin/bash
echo "Setting up development environment..."

# Install dependencies
npm install

# Start development server
npm run dev

echo "Development server started on http://localhost:3000"
```

## Tables

### Basic Tables

| Feature | Supported | Notes |
|---------|-----------|-------|
| Markdown | ✅ | Full CommonMark support |
| Wikilinks | ✅ | Obsidian-style double brackets |
| Callouts | ✅ | Multiple types with icons |
| Math | ❌ | Not implemented yet |
| Diagrams | 🔄 | Planned for future release |

### Advanced Tables

| Language | Use Case | Performance | Learning Curve |
|----------|----------|-------------|----------------|
| JavaScript | Web Development | ⭐⭐⭐⭐ | Easy |
| Python | Data Science | ⭐⭐⭐ | Easy |
| Rust | Systems Programming | ⭐⭐⭐⭐⭐ | Hard |
| Go | Backend Services | ⭐⭐⭐⭐ | Medium |

## Blockquotes

### Simple Quotes

> The best way to predict the future is to invent it.
> — Alan Kay

### Nested Quotes

> This is a top-level quote.
> 
> > This is a nested quote within the first quote.
> > 
> > > And this is a quote nested even deeper.
> 
> Back to the top level.

## Horizontal Rules

You can create horizontal rules using three dashes:

---

Or three asterisks:

***

Or three underscores:

___

## Keyboard Shortcuts

Press <kbd>Ctrl</kbd> + <kbd>C</kbd> to copy and <kbd>Ctrl</kbd> + <kbd>V</kbd> to paste.

Use <kbd>Cmd</kbd> + <kbd>K</kbd> to open the command palette.

## Special Characters and Symbols

- Copyright: ©
- Trademark: ™
- Registered: ®
- Arrows: ← ↑ → ↓ ↔ ↕
- Symbols: ★ ☆ ♠ ♣ ♥ ♦
- Currency: $ € £ ¥

## HTML Elements

Sometimes you need to use HTML for more complex formatting:

<details>
<summary>Click to expand</summary>

This content is hidden by default and can be expanded by clicking the summary.

</details>

<mark>Highlighted text using HTML</mark>

<small>Small text for fine print</small>

## Conclusion

This comprehensive guide covers most of the markdown features available in our Obsidian-inspired blog theme. The combination of standard markdown, extended syntax, and Obsidian-compatible features provides a powerful writing environment for creating rich, engaging content.

### Quick Reference

- **Bold**: `**text**` or `__text__`
- **Italic**: `*text*` or `_text_`
- **Code**: `` `code` ``
- **Links**: `[text](url)` or `[[wikilink]]`
- **Images**: `![alt](url)`
- **Lists**: `-` or `1.` for ordered
- **Tasks**: `- [ ]` and `- [x]`
- **Tables**: Use `|` to separate columns
- **Quotes**: Start lines with `>`
- **Callouts**: `> [!TYPE]`
- **Horizontal rule**: `---`

Happy writing! 🚀
