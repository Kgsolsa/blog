import { defineCollection, z } from 'astro:content';

// Define schema for blog posts
const postsCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    date: z.date(),
    tags: z.array(z.string()).optional(),
    draft: z.boolean().optional(),
    image: z.string().optional(),
    imageOG: z.boolean().optional(),
    imageAlt: z.string().optional(),
    hideCoverImage: z.boolean().optional(),
    targetKeyword: z.string().optional(),
    author: z.string().optional(),
    noIndex: z.boolean().optional(),
  }),
});

// Define schema for static pages
const pagesCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    draft: z.boolean().optional(),
    lastModified: z.date().optional(),
    image: z.string().optional(),
    imageAlt: z.string().optional(),
    hideCoverImage: z.boolean().optional(),
    noIndex: z.boolean().optional(),
  }),
});

// Export collections
export const collections = {
  posts: postsCollection,
  pages: pagesCollection,
};