---
title: Getting Started
date: 2025-09-07
description: Everything you need to know to set up, configure, and customize Astro Modular.
tags:
  - tutorial
  - setup
  - configuration
  - astro
  - blog
  - obsidian
image: "[[images/sunset.jpg]]"
imageAlt: Sunset skyline.
imageOG: true
hideCoverImage: false
targetKeyword: astro blog setup
draft: false
---
This guide covers everything needed to set up and customize your modular Astro blog, designed for Obsidian users who want to publish content with minimal friction.

## Prerequisites & Setup

You'll need:
- **Node.js 18+**
- **pnpm** (recommended) or npm
- Basic markdown familiarity
- Obsidian (optional)

### Installation

```bash
# Install dependencies
pnpm install

# Start development server
pnpm run dev
# Available at http://localhost:5000

# Build for production
pnpm run build
```

## Configuration

### Core Settings

Configure everything in `src/config.ts`. The configuration is organized in logical sections:

```typescript
export const siteConfig = {
  site: 'https://yourdomain.com',
  title: 'Your Blog Title',
  description: 'Your blog description',
  author: 'Your Name',  // Global author for all posts
  language: 'en',
}
```

## Customization

### Theme & Layout

Select theme and layout options in the config:

```
theme: "oxygen",
layout: {
  contentWidth: "45rem",
},
postsPerPage: 5,
recentPostsCount: 3,
seo: {
    defaultOgImageAlt: "Astro Modular logo.",
  },
homeBlurb: {
  enabled: true,
  placement: "below", // 'above' or 'below'
},
footer: {
  content: `© 2025 {author}. Built with Astro Modular.`,
}
```

The theme options are currently Oxygen, Minimal, Atom, Ayu, Catppuccin, Charcoal, Dracula, Everforest, Flexoki, Gruvbox, macOS, Nord, Obsidian, Rosé Pine, Sky, Solarized, and Things. You may need to do a hard refresh (`CTRL + SHIFT + R`) to see the changes.

### Typography Configuration

Customize fonts for headings and body text:

```typescript
typography: {
  headingFont: "Inter", // Font for headings (h1, h2, h3, h4, h5, h6)
  proseFont: "Inter",   // Font for body text and prose content
}
```

**Suggested Font Combinations:**
- **Default**: `headingFont: "Inter"`, `proseFont: "Inter"`
- **Modern: `headingFont: "Montserrat"`, `proseFont: "Lato"`
- **Elegant: `headingFont: "Playfair Display"`, `proseFont: "Source Sans Pro"`
- **Serif: `headingFont: "Merriweather"`, `proseFont: "Merriweather"`

**Supported Fonts:**
- **Sans-Serif**: Inter, Roboto, Open Sans, Lato, Poppins, Source Sans Pro, Nunito, Montserrat
- **Serif**: Playfair Display, Merriweather, Lora, Crimson Text, PT Serif, Libre Baskerville
- **Monospace**: Fira Code, JetBrains Mono, Source Code Pro, IBM Plex Mono, Cascadia Code

The system automatically loads Google Fonts when needed and provides fallbacks to system fonts for optimal performance.

### Modular Features

Adjust modular features in the config: 

```
features: {
    flags: {
      readingTime: true,
      wordCount: true,
      tableOfContents: true,
      tags: true,
      linkedMentions: true,
      scrollToTop: true,
      darkModeToggleButton: true,
      commandPalette: true,
      postNavigation: true,
      showLatestPost: true,
      showSocialIconsInFooter: true,
    },
    showCoverImages: "latest-and-posts",
  },
```

**Cover Image Options:**
- `"all"` - Show cover images everywhere
- `"latest"` - Show only on the latest post section and featured posts
- `"home"` - Show on homepage sections (latest and recent)
- `"posts"` - Show only on posts pages, tag pages, and post listings
- `"latest-and-posts"` - Show on latest post section AND posts pages/tags (but not recent posts section)
- `"none"` - Never show cover images

**Post Card Aspect Ratio:**
Configure the aspect ratio for post card cover images:

```typescript
features: {
  postCardAspectRatio: "og", // Default: OpenGraph standard
  customAspectRatio: undefined, // For custom ratios
}
```

**Aspect Ratio Options:**
- `"og"` (1.91:1) - OpenGraph standard (default)
- `"16:9"` (1.78:1) - Standard widescreen
- `"4:3"` (1.33:1) - Traditional
- `"3:2"` (1.5:1) - Classic photography
- `"square"` (1:1) - Square
- `"golden"` (1.618:1) - Golden ratio
- `"custom"` - Use your own ratio

**Custom Aspect Ratio Example:**
```typescript
postCardAspectRatio: "custom",
customAspectRatio: "2.5/1" // Custom 2.5:1 ratio
```

*Note: This only affects post cards (listings, homepage, tag pages). Individual post cover images maintain their original aspect ratio.*

### Comments System

The theme includes a Giscus-powered commenting system that uses GitHub Discussions. Here's how to set it up:

#### Enable Comments

In your `src/config.ts`, enable comments:

```typescript
features: {
  comments: true,  // Enable/disable comments
}
```

#### GitHub Setup

1. **Enable Discussions on Your Repository**:
   - Go to your GitHub repository
   - Click **Settings** → **General**
   - Scroll to **"Features"** section
   - Check **"Discussions"** and click **"Set up discussions"**

2. **Create a Discussion Category**:
   - Go to **Discussions** tab in your repository
   - Click **"New category"**
   - Name it **"General"**
   - Set format to **"Announcement"** (prevents random users from creating new discussions)
   - Description: "Comments on blog posts"

3. **Get Giscus Configuration**:
   - Visit [giscus.app](https://giscus.app)
   - Enter your repository: `username/repo-name`
   - Select **"General"** as the discussion category
   - Copy the generated **Repository ID** and **Category ID**

4. **Update Your Config**:
   ```typescript
   comments: {
     provider: "giscus",
     repo: "username/repo-name",        // Your GitHub repository
     repoId: "R_kgDO...",              // Repository ID from Giscus
     category: "General",               // Discussion category
     categoryId: "DIC_kwDO...",        // Category ID from Giscus
     mapping: "pathname",               // How posts map to discussions
     strict: "0",                      // Allow comments on any post
     reactions: "1",                   // Enable reactions
     metadata: "0",                    // Hide discussion metadata
     inputPosition: "bottom",          // Comment input position
     theme: "preferred_color_scheme",  // Follows user's theme preference
     lang: "en",                       // Language
     loading: "lazy",                  // Lazy load comments
   }
   ```

#### How It Works

- **Each blog post** automatically creates a GitHub discussion
- **Visitors need GitHub accounts** to comment
- **Comments appear** both on your blog and in GitHub Discussions
- **You moderate** through GitHub's interface
- **"Announcement" format** prevents random discussion creation

#### Moderation & Control

- **Delete comments** directly in GitHub Discussions
- **Block users** through GitHub's user management
- **Lock discussions** to prevent new comments
- **Pin important comments** to the top
- **Use GitHub's content policies** for automatic moderation

#### Privacy Considerations

Comments are publicly visible and associated with users' GitHub profiles. Consider adding a privacy policy section about comments (see the included Privacy Policy page for reference).

### Navigation

Navigation is also set in the config:

```
navigation: {
  showNavigation: true,
  style: 'traditional', // or 'minimal'
  showMobileMenu: true,
  pages: [
    { title: 'Posts', url: '/posts' },
    { title: 'About', url: '/about' }
  ],
  social: [
    { title: 'GitHub', url: 'https://github.com/username', icon: 'github' }
  ],
}
```
## Content Structure

```
src/content/
├── posts/           # Blog posts
│   ├── images/      # Post images
│   └── *.md         # Markdown files
├── pages/           # Static pages
│   ├── images/      # Page images
│   └── *.md         # Markdown files
└── .obsidian/       # Obsidian vault setup
```

## Writing Posts

Create posts in `src/content/posts/` with this frontmatter:

```markdown
---
title: "{{title}}"
date: {{date}}
description: ""
tags: []
image: ""
imageAlt: ""
imageOG: false
hideCoverImage: false
targetKeyword: ""
draft: true
---

## Start with H2 Headings

Write using markdown with enhanced features.

Use [[wikilinks]] to connect posts.

> [!note] Obsidian Callouts
> Work exactly like in Obsidian!
```

Since the post title is hardcoded as H1, your content should start with H2 headings.

You can also create folder-based posts, as you can see here: [Sample Folder-Based Post](posts/sample-folder-post/index.md). The base filename is `index.md` and the parent folder filename serves as the slug of the post.
## Creating Pages 

The About page represents a standard page you can duplicate easily. Its frontmatter looks like this: 

```markdown
---
title: "{{title}}"
description: ""
noIndex: false
---

## Start with H2 Headings

Write using markdown with enhanced features.
```

H1s are hardcoded from the title frontmatter like posts, but pages get a unique `noIndex` property that sets whether or not the page should be indexed in search engines or included on the sitemap. Helpful for pages that you don't want indexed like a thank-you page.

### Automatic Aliases & Redirects

When you rename a post or page in Obsidian, the old filename is automatically stored as an alias. Astro processes these aliases and creates redirect rules, so old URLs continue to work. You don't need to add aliases manually - they appear automatically when you use Obsidian's rename functionality.

### Other Page Details

The Contact page has an optional form embedded into it, which leads to the Thank You page when filled out. It's preconfigured to work with Netlify out of the box, you just have to [enable form detection](https://docs.netlify.com/manage/forms/setup/) on your project.

An optional Privacy Policy page can be edited or removed by deleting it if you don't want it. 

`index.md` controls what goes on the homepage blurb. Adding content to `404.md` will display on any "not found" page.
## Obsidian Integration

### Using the Included Vault

1. Open `src/content/` in Obsidian
2. Trust author and enable plugins (Astro Composer, Minimal theme)
3. Start writing

The vault provides:
- **Preconfigured plugins** optimized for this Astro blog
- **Adjustable theme** for distraction-free writing
- **Optional CSS snippets** to customize your experience
- **Custom hotkeys** for accelerating post creation and publishing

Read [the guide](posts/astro-suite-vault-modular-guide.md) for more detailed information.

To remove Obsidian, simply delete the `.obsidian` folder.

## Key Features

### Command Palette
Press `Ctrl+K` (or custom hotkey) for instant navigation, search, and dark/light mode switching.

### Wikilinks & Connections
- `[[Post Title]]` - Standard wikilink
- `[[Post Title|Custom Text]]` - Custom display text
- **Linked mentions** show post connections automatically

### Image Optimization
- **WebP conversion** for performance
- **Responsive grids** for multiple images
- **Lazy loading** built-in

### SEO & Performance
- **Automatic sitemaps** and RSS feeds
- **Open Graph** meta tags
- **Optimized for performance and accessibility**
- **Static generation**

## Content Organization

### Tags
Tags sync between Obsidian and your blog, creating:
- Tag pages for related posts
- Command palette filtering
- Organized navigation

### Drafts
- **Development**: All posts visible
- **Production**: Only published posts
- Use `draft: true` in frontmatter to hide

## Deployment

```bash
pnpm run build
```

Generates a static site ready for any hosting platform with automatic optimization.
## Troubleshooting

Common issues:
- **Image paths**: Check folder structure in `src/content/posts/images/`
- **Wikilinks**: Ensure target posts exist and are published
- **Build errors**: Verify frontmatter syntax

## Next Steps

1. **Customize** `src/config.ts`
2. **Write** your first post
3. **Explore** [Formatting Reference](formatting-reference.md)
4. **Set up** Obsidian vault workflow
5. **Deploy** and share

Your modular Astro blog is ready for your content!