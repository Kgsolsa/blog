import type { Post, WikilinkMatch } from '@/types';
import { visit } from 'unist-util-visit';

// Utility functions for content-aware URL processing
function isFolderBasedContent(collection: 'posts' | 'pages', slug: string, allContent: any[]): boolean {
  const content = allContent.find(item => item.slug === slug);
  return content ? content.id.endsWith('/index') : false;
}

function shouldRemoveIndexFromUrl(url: string, allPosts: any[], allPages: any[]): boolean {
  // Determine collection type from URL
  if (url.startsWith('/posts/')) {
    const slug = url.replace('/posts/', '').split('#')[0]; // Remove anchor
    return isFolderBasedContent('posts', slug, allPosts);
  } else if (url.startsWith('/pages/')) {
    const slug = url.replace('/pages/', '').split('#')[0]; // Remove anchor
    return isFolderBasedContent('pages', slug, allPages);
  }
  return false; // Don't remove /index for other URLs
}

// Remark plugin for processing wikilinks
export function remarkWikilinks() {
  return function transformer(tree: any, file: any) {
    const nodesToReplace: Array<{ parent: any; index: number; newChildren: any[] }> = [];

    visit(tree, 'text', (node: any, index: any, parent: any) => {
      if (!node.value || typeof node.value !== 'string') {
        return;
      }

      // Skip wikilink processing if we're inside a code block
      if (isInsideCodeBlock(parent, tree)) {
        return;
      }

      // Process both link wikilinks [[...]] and image wikilinks ![[...]]
      const wikilinkRegex = /!?\[\[([^\]]+)\]\]/g;
      let match;
      const newChildren: any[] = [];
      let lastIndex = 0;
      let hasWikilinks = false;
      

      while ((match = wikilinkRegex.exec(node.value)) !== null) {
        hasWikilinks = true;
        const [fullMatch, content] = match;
        const isImageWikilink = fullMatch.startsWith('!');
        const [link, displayText] = content.includes('|')
          ? content.split('|', 2)
          : [content, null]; // null means we'll resolve it later

        // Add text before the wikilink
        if (match.index > lastIndex) {
          newChildren.push({
            type: 'text',
            value: node.value.slice(lastIndex, match.index)
          });
        }

        const linkText = link.trim();
        const finalDisplayText = displayText ? displayText.trim() : linkText;

        if (isImageWikilink) {
          // Process image wikilink - convert to markdown image syntax
          // Use the image path as-is (Obsidian doesn't use ./ by default)
          const imagePath = linkText;
          const altText = displayText || linkText;
          
          // Create a proper image node that Astro can process
          newChildren.push({
            type: 'image',
            url: imagePath,
            alt: altText,
            title: null,
            data: {
              hName: 'img',
              hProperties: {
                src: imagePath,
                alt: altText
              }
            }
          });
        } else {
          // Process link wikilink
          const { link, anchor } = parseLinkWithAnchor(linkText);
          
          // Handle different link formats
          let url: string;
          let wikilinkData: string;
          
          if (link.startsWith('posts/')) {
            // Handle posts/path format
            const postPath = link.replace('posts/', '');
            // Conservative approach: only remove /index if it follows folder-based pattern
            // Pattern: folder-name/index -> folder-name (where folder-name matches the slug)
            const cleanPath = postPath.endsWith('/index') && postPath.split('/').length === 2 
              ? postPath.replace('/index', '') 
              : postPath;
            url = `/posts/${cleanPath}`;
            wikilinkData = cleanPath;
          } else if (link.includes('/')) {
            // Handle other path formats
            const slugifiedLink = createSlugFromTitle(link);
            url = `/posts/${slugifiedLink}`;
            wikilinkData = link.trim();
          } else {
            // Handle simple slug format
            const slugifiedLink = createSlugFromTitle(link);
            url = `/posts/${slugifiedLink}`;
            wikilinkData = link.trim();
          }
          
          // Add anchor if present
          if (anchor) {
            const anchorSlug = createAnchorSlug(anchor);
            url += `#${anchorSlug}`;
          }

          // Add the wikilink as a link node
          // We'll use the link text as placeholder - the actual resolution happens in PostLayout
          newChildren.push({
            type: 'link',
            url: url,
            title: null,
            data: {
              hName: 'a',
              hProperties: {
                className: ['wikilink'],
                'data-wikilink': wikilinkData,
                'data-display-override': displayText
              }
            },
            children: [{
              type: 'text',
              value: displayText || link.trim()
            }]
          });
        }

        lastIndex = wikilinkRegex.lastIndex;
      }

      // Add remaining text
      if (lastIndex < node.value.length) {
        newChildren.push({
          type: 'text',
          value: node.value.slice(lastIndex)
        });
      }

      if (hasWikilinks && parent && parent.children) {
        nodesToReplace.push({
          parent,
          index,
          newChildren
        });
      }
    });

    // Process existing link nodes to add wikilink data attributes for internal links
    visit(tree, 'link', (node: any) => {
      if (node.url && isInternalLink(node.url)) {
        const { linkText, anchor } = extractLinkTextFromUrlWithAnchor(node.url);
        if (linkText) {
          // Convert .md file references to proper /posts/ URLs
          if (node.url.endsWith('.md') || node.url.includes('.md#')) {
            // Handle both direct .md references and posts/...md references
            if (node.url.startsWith('posts/')) {
              // Already has posts/ prefix, just remove .md and add leading slash
              let baseUrl = `/${node.url.replace(/\.md.*$/, '')}`;
              // Conservative approach: only remove /index if it follows folder-based pattern
              if (baseUrl.endsWith('/index') && baseUrl.split('/').length === 3) {
                baseUrl = baseUrl.replace('/index', '');
              }
              if (anchor) {
                baseUrl += `#${createAnchorSlug(anchor)}`;
              }
              node.url = baseUrl;
            } else {
              // Direct .md reference, convert to /posts/ URL
              let baseUrl = `/posts/${linkText}`;
              // Conservative approach: only remove /index if it follows folder-based pattern
              if (baseUrl.endsWith('/index') && baseUrl.split('/').length === 3) {
                baseUrl = baseUrl.replace('/index', '');
              }
              if (anchor) {
                baseUrl += `#${createAnchorSlug(anchor)}`;
              }
              node.url = baseUrl;
            }
          } else if (anchor) {
            // Handle anchors in non-.md URLs
            node.url += `#${createAnchorSlug(anchor)}`;
          }

          // Add wikilink data attributes to make it work with linked mentions
          if (!node.data) {
            node.data = {};
          }
          if (!node.data.hProperties) {
            node.data.hProperties = {};
          }

          // Add wikilink class and data attributes
          const existingClasses = node.data.hProperties.className || [];
          node.data.hProperties.className = Array.isArray(existingClasses)
            ? [...existingClasses, 'wikilink']
            : [existingClasses, 'wikilink'].filter(Boolean);

          node.data.hProperties['data-wikilink'] = linkText;
          // For standard markdown links, we don't have a display override
          node.data.hProperties['data-display-override'] = null;
        }
      }
    });

    // Replace nodes with wikilinks
    nodesToReplace.reverse().forEach(({ parent, index, newChildren }) => {
      if (parent && parent.children && Array.isArray(parent.children)) {
        parent.children.splice(index, 1, ...newChildren);
      }
    });
  };
}

// Create slug from title for wikilink resolution
function createSlugFromTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Create anchor slug from text (for heading anchors)
function createAnchorSlug(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}

// Parse link with potential anchor fragment
function parseLinkWithAnchor(linkText: string): { link: string; anchor: string | null } {
  const anchorIndex = linkText.indexOf('#');
  if (anchorIndex === -1) {
    return { link: linkText, anchor: null };
  }
  
  const link = linkText.substring(0, anchorIndex);
  const anchor = linkText.substring(anchorIndex + 1);
  
  return { link, anchor };
}

// Extract wikilinks and standard markdown links from content
export function extractWikilinks(content: string): WikilinkMatch[] {
  const matches: WikilinkMatch[] = [];

  // Extract wikilinks [[...]] and image wikilinks ![[...]]
  const wikilinkRegex = /!?\[\[([^\]]+)\]\]/g;
  let wikilinkMatch;

  while ((wikilinkMatch = wikilinkRegex.exec(content)) !== null) {
    const [fullMatch, linkContent] = wikilinkMatch;
    const isImageWikilink = fullMatch.startsWith('!');

    // Skip if wikilink is inside backticks (code)
    if (isWikilinkInCode(content, wikilinkMatch.index)) {
      continue;
    }

    // Only process link wikilinks for linked mentions, not image wikilinks
    if (!isImageWikilink) {
      const [link, displayText] = linkContent.includes('|')
        ? linkContent.split('|', 2)
        : [linkContent, linkContent];

      // Parse anchor if present
      const { link: baseLink } = parseLinkWithAnchor(link.trim());

      // Create proper slug for linked mentions
      let slug = baseLink;
      if (baseLink.startsWith('posts/')) {
        const postPath = baseLink.replace('posts/', '');
        // Conservative approach: only remove /index if it follows folder-based pattern
        if (postPath.endsWith('/index') && postPath.split('/').length === 2) {
          slug = postPath.replace('/index', '');
        } else {
          slug = postPath;
        }
      }
      
      // Convert to slug format
      const finalSlug = slug.toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/-+/g, '-')
        .replace(/^-+|-+$/g, '');

      matches.push({
        link: baseLink,
        display: displayText.trim(),
        slug: finalSlug
      });
    }
  }

  // Extract standard markdown links [text](url) that point to internal posts
  const markdownLinkRegex = /\[([^\]]+)\]\(([^)]+)\)/g;
  let markdownMatch;

  while ((markdownMatch = markdownLinkRegex.exec(content)) !== null) {
    const [fullMatch, displayText, url] = markdownMatch;

    // Skip if markdown link is inside backticks (code)
    if (isWikilinkInCode(content, markdownMatch.index)) {
      continue;
    }

    // Check if this is an internal link (relative path or pointing to a post)
    if (isInternalLink(url)) {
      const { linkText } = extractLinkTextFromUrlWithAnchor(url);
      if (linkText) {
        // Create proper slug for linked mentions
        let slug = linkText;
        if (linkText.startsWith('posts/')) {
          const postPath = linkText.replace('posts/', '');
          // Conservative approach: only remove /index if it follows folder-based pattern
          if (postPath.endsWith('/index') && postPath.split('/').length === 2) {
            slug = postPath.replace('/index', '');
          } else {
            slug = postPath;
          }
        }
        
        // Convert to slug format
        const finalSlug = slug.toLowerCase()
          .replace(/[^a-z0-9\s-]/g, '')
          .replace(/\s+/g, '-')
          .replace(/-+/g, '-')
          .replace(/^-+|-+$/g, '');


        matches.push({
          link: linkText,
          display: displayText.trim(),
          slug: finalSlug
        });
      }
    }
  }

  return matches;
}

// Find linked mentions (backlinks) for a post
export function findLinkedMentions(posts: Post[], targetSlug: string, allPosts: any[] = [], allPages: any[] = []) {
  const mentions = posts
    .filter(post => post.slug !== targetSlug)
    .map(post => {
      const wikilinks = extractWikilinks(post.body);
      const matchingLinks = wikilinks.filter(link => link.slug === targetSlug);

      if (matchingLinks.length > 0) {
        return {
          title: post.data.title,
          slug: post.slug,
          excerpt: createExcerptAroundWikilink(post.body, matchingLinks[0].link, allPosts, allPages)
        };
      }
      return null;
    })
    .filter(Boolean);

  return mentions;
}

// Create excerpt around wikilink for context
function createExcerptAroundWikilink(content: string, linkText: string, allPosts: any[] = [], allPages: any[] = []): string {
  // Remove frontmatter
  const withoutFrontmatter = content.replace(/^---\n[\s\S]*?\n---\n/, '');

  // Try to find wikilink pattern first
  const wikilinkPattern = `\\[\\[${linkText}[^\\]]*\\]\\]`;
  const wikilinkRegex = new RegExp(wikilinkPattern, 'i');

  let match;
  let searchStart = 0;

  // Find the wikilink that's not in code
  while ((match = wikilinkRegex.exec(withoutFrontmatter.slice(searchStart))) !== null) {
    const actualIndex = searchStart + match.index!;

    // Check if this wikilink is inside backticks
    if (!isWikilinkInCode(withoutFrontmatter, actualIndex)) {
      return extractExcerptAtPosition(withoutFrontmatter, actualIndex, match[0].length);
    }

    searchStart = actualIndex + match[0].length;
    wikilinkRegex.lastIndex = 0; // Reset regex for next search
  }

  // If no wikilink found, try to find standard markdown links that point to this linkText
  const markdownLinkRegex = /\[([^\]]+)\]\(([^)]+)\)/g;
  let markdownMatch;

  while ((markdownMatch = markdownLinkRegex.exec(withoutFrontmatter)) !== null) {
    const [fullMatch, displayText, url] = markdownMatch;

    // Check if this markdown link is inside backticks
    if (!isWikilinkInCode(withoutFrontmatter, markdownMatch.index)) {
      // Check if this URL points to our target linkText
      if (isInternalLink(url)) {
        const { linkText: urlLinkText } = extractLinkTextFromUrlWithAnchor(url, allPosts, allPages);
        if (urlLinkText) {
          // Normalize both linkText and urlLinkText for comparison
          const normalizedLinkText = linkText.replace(/\/index$/, '');
          const normalizedUrlLinkText = urlLinkText.replace(/\/index$/, '');
          
          
          if (normalizedUrlLinkText === normalizedLinkText || urlLinkText === linkText) {
            return extractExcerptAtPosition(withoutFrontmatter, markdownMatch.index, fullMatch.length);
          }
        }
      }
    }
  }

  return '';
}

// Helper function to extract excerpt at a specific position
function extractExcerptAtPosition(content: string, position: number, linkLength: number): string {
  const contextLength = 100;

  // Get context around the match
  const start = Math.max(0, position - contextLength);
  const end = Math.min(content.length, position + linkLength + contextLength);

  let excerpt = content.slice(start, end);

  // Clean up excerpt
  excerpt = excerpt
    .replace(/^\S*\s*/, '') // Remove partial word at start
    .replace(/\s*\S*$/, '') // Remove partial word at end
    .replace(/\n+/g, ' ') // Replace newlines with spaces
    .trim();

  return excerpt;
}

// Resolve wikilink to actual post
export function resolveWikilink(posts: Post[], linkText: string): Post | null {
  const targetSlug = createSlugFromTitle(linkText);

  // First try exact slug match
  let post = posts.find(p => p.slug === targetSlug);

  // If not found, try title match
  if (!post) {
    post = posts.find(p =>
      createSlugFromTitle(p.data.title) === targetSlug
    );
  }

  return post || null;
}

// Validate wikilinks in content
export function validateWikilinks(posts: Post[], content: string): {
  valid: WikilinkMatch[];
  invalid: WikilinkMatch[];
} {
  const wikilinks = extractWikilinks(content);
  const valid: WikilinkMatch[] = [];
  const invalid: WikilinkMatch[] = [];

  wikilinks.forEach(wikilink => {
    const resolved = resolveWikilink(posts, wikilink.link);
    if (resolved) {
      valid.push(wikilink);
    } else {
      invalid.push(wikilink);
    }
  });

  return { valid, invalid };
}

// Helper function to check if a node is inside a code block
function isInsideCodeBlock(parent: any, tree: any): boolean {
  // Check if the immediate parent is a code-related node
  if (!parent) return false;

  // Check for inline code or code blocks
  if (parent.type === 'inlineCode' || parent.type === 'code') {
    return true;
  }

  // Walk up the AST to check for code block ancestors
  let currentNode = parent;
  while (currentNode) {
    if (currentNode.type === 'inlineCode' || currentNode.type === 'code') {
      return true;
    }
    // Try to find the parent node in the tree (simplified check)
    currentNode = currentNode.parent;
  }

  return false;
}

// Helper function to check if a wikilink is inside backticks in raw content
function isWikilinkInCode(content: string, wikilinkIndex: number): boolean {
  // Find all backtick pairs in the content
  const backtickRegex = /`([^`]*)`/g;
  let match;

  while ((match = backtickRegex.exec(content)) !== null) {
    const codeStart = match.index;
    const codeEnd = match.index + match[0].length;

    // Check if the wikilink is inside this code block
    if (wikilinkIndex >= codeStart && wikilinkIndex < codeEnd) {
      return true;
    }
  }

  return false;
}

// Helper function to check if a URL is an internal link
function isInternalLink(url: string): boolean {
  // Remove any leading/trailing whitespace
  url = url.trim();

  // Skip external URLs (http/https)
  if (url.startsWith('http://') || url.startsWith('https://')) {
    return false;
  }

  // Skip email links
  if (url.startsWith('mailto:')) {
    return false;
  }

  // Skip anchors only
  if (url.startsWith('#')) {
    return false;
  }

  // Parse anchor if present to check the base URL
  const { link } = parseLinkWithAnchor(url);

  // Check if it's a post link (ends with .md, starts with /posts/, or is a slug)
  const isInternal = link.endsWith('.md') || link.startsWith('/posts/') || link.startsWith('posts/') || !link.includes('/');
  
  
  return isInternal;
}

// Helper function to extract link text from URL for internal links
function extractLinkTextFromUrl(url: string, allPosts: any[] = [], allPages: any[] = []): string | null {
  const result = extractLinkTextFromUrlWithAnchor(url, allPosts, allPages);
  return result.linkText;
}

// Helper function to extract link text and anchor from URL for internal links
function extractLinkTextFromUrlWithAnchor(url: string, allPosts: any[] = [], allPages: any[] = []): { linkText: string | null; anchor: string | null } {
  url = url.trim();
  
  // Parse anchor if present
  const { link, anchor } = parseLinkWithAnchor(url);

  // Handle posts/ prefixed links first
  if (link.startsWith('posts/')) {
    let linkText = link.replace('posts/', '').replace(/\.md$/, '');
    // Conservative approach: only remove /index if it follows folder-based pattern
    if (linkText.endsWith('/index') && linkText.split('/').length === 2) {
      linkText = linkText.replace('/index', '');
    }
    return {
      linkText: linkText,
      anchor: anchor
    };
  }
  
  // Handle .md files - these should be treated as post references
  if (link.endsWith('.md')) {
    let linkText = link.replace(/\.md$/, '');
    // Conservative approach: only remove /index if it follows folder-based pattern
    if (linkText.endsWith('/index') && linkText.split('/').length === 1) {
      linkText = linkText.replace('/index', '');
    }
    return {
      linkText: linkText,
      anchor: anchor
    };
  }

  // Handle /posts/ URLs
  if (link.startsWith('/posts/')) {
    return {
      linkText: link.replace('/posts/', ''),
      anchor: anchor
    };
  }

  // If it's just a slug (no slashes), use it directly
  if (!link.includes('/')) {
    return {
      linkText: link,
      anchor: anchor
    };
  }

  return { linkText: null, anchor: null };
}

// Process HTML content to resolve wikilink display text with post titles
export function processWikilinksInHTML(posts: Post[], html: string, allPosts: any[] = [], allPages: any[] = []): string {
  // Just return the HTML unchanged - let client-side handle all display text logic
  return html;
}

// Content-aware wikilinks processing for use in layouts where content collections are available
export function processContentAwareWikilinks(content: string, allPosts: any[], allPages: any[]): string {
  // This function can be used to process wikilinks with full content collection awareness
  // For now, we'll use the existing remarkWikilinks plugin but with content collections
  // In the future, this could be enhanced to do more sophisticated processing
  
  // The actual processing happens in the remarkWikilinks plugin during markdown rendering
  // This function is a placeholder for future enhancements
  return content;
}

// Custom remark plugin to handle folder-based post images
export function remarkFolderImages() {
  return function transformer(tree: any, file: any) {
    visit(tree, 'image', (node: any) => {
      // Check if this is a folder-based post by looking at the file path
      const isFolderPost = file.path && file.path.includes('/posts/') && file.path.endsWith('/index.md');
      
      if (isFolderPost && node.url && !node.url.startsWith('/') && !node.url.startsWith('http')) {
        // Extract the post slug from the file path
        const pathParts = file.path.split('/');
        const postsIndex = pathParts.indexOf('posts');
        const postSlug = pathParts[postsIndex + 1];
        
        // Handle both relative paths and subdirectory paths
        let imagePath = node.url;
        
        // Remove leading './' if present
        if (imagePath.startsWith('./')) {
          imagePath = imagePath.slice(2);
        }
        
        // Update the image URL to point to the correct folder (preserving subdirectory structure)
        node.url = `/posts/${postSlug}/${imagePath}`;
        
        // Also update the hProperties if they exist (for wikilink images)
        if (node.data && node.data.hProperties) {
          node.data.hProperties.src = node.url;
        }
      }
    });
  };
}

// Custom remark plugin to process image captions
export function remarkImageCaptions() {
  return function transformer(tree: any) {
    visit(tree, 'image', (node: any) => {
      // If the image has a title attribute, store it as caption data
      if (node.title) {
        if (!node.data) {
          node.data = {};
        }
        if (!node.data.hProperties) {
          node.data.hProperties = {};
        }
        node.data.hProperties['data-caption'] = node.title;
        node.data.hProperties.title = node.title;
      }
    });
  };
}