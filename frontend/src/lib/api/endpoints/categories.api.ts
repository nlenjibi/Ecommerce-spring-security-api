import { request } from '../core/client';
import { StandardResponse } from '../core/types';

export interface Category {
  id: number;
  name: string;
  slug: string;
  description?: string;
  image?: string;
  parentId?: number;
  children?: Category[];
  productCount?: number;
}

/**
 * Categories API
 */
export const categoriesApi = {
  /**
   * Get all categories
   */
  getAll: (params?: {
    page?: number;
    limit?: number;
    includeProducts?: boolean;
    parentId?: number;
  }) =>
    request<StandardResponse<Category[]> & { total: number }>({
      method: 'GET',
      url: '/v1/categories',
      params,
    }),

  /**
   * Get category by ID
   */
  getById: (id: number) =>
    request<StandardResponse<Category>>({
      method: 'GET',
      url: `/v1/categories/${id}`,
    }),

  /**
   * Get category by slug
   */
  getBySlug: (slug: string) =>
    request<StandardResponse<Category>>({
      method: 'GET',
      url: `/v1/categories/slug/${slug}`,
    }),

  /**
   * Create category
   */
  create: (data: {
    name: string;
    slug?: string;
    description?: string;
    parentId?: number;
    image?: string;
  }) =>
    request<StandardResponse<Category>>({
      method: 'POST',
      url: '/v1/categories',
      data,
    }),

  /**
   * Update category
   */
  update: (id: number, data: Partial<{
    name: string;
    slug: string;
    description: string;
    parentId: number;
    image: string;
  }>) =>
    request<StandardResponse<Category>>({
      method: 'PUT',
      url: `/v1/categories/${id}`,
      data,
    }),

  /**
   * Delete category
   */
  delete: (id: number) =>
    request<StandardResponse<null>>({
      method: 'DELETE',
      url: `/v1/categories/${id}`,
    }),

  /**
   * Get category tree
   */
  getTree: () =>
    request<StandardResponse<Category[]>>({
      method: 'GET',
      url: '/v1/categories/tree',
    }),

  /**
   * Get products in category
   */
  getProducts: (categoryId: number, params?: {
    page?: number;
    limit?: number;
    sortBy?: string;
    direction?: string;
  }) =>
    request<{
      products: any[];
      total: number;
      page: number;
      totalPages: number;
    }>({
      method: 'GET',
      url: `/v1/categories/${categoryId}/products`,
      params,
    }),

  /**
   * Get root categories
   */
  getRoot: () =>
    request<StandardResponse<Category[]>>({
      method: 'GET',
      url: '/v1/categories/root',
    }),

  /**
   * Get active categories
   */
  getActive: () =>
    request<StandardResponse<Category[]>>({
      method: 'GET',
      url: '/v1/categories/active',
    }),

  /**
   * Search categories
   */
  search: (keyword: string) =>
    request<StandardResponse<Category[]>>({
      method: 'GET',
      url: '/v1/categories/search',
      params: { keyword },
    }),

  /**
   * Get child categories
   */
  getChildren: (parentId: number) =>
    request<StandardResponse<Category[]>>({
      method: 'GET',
      url: `/v1/categories/${parentId}/children`,
    }),

  /**
   * Get category hierarchy
   */
  getHierarchy: () =>
    request<StandardResponse<Category[]>>({
      method: 'GET',
      url: '/v1/categories/hierarchy',
    }),

  /**
   * Create parent category
   */
  createParent: (data: {
    name: string;
    description?: string;
    imageUrl?: string;
    displayOrder?: number;
  }) =>
    request<StandardResponse<Category>>({
      method: 'POST',
      url: '/v1/categories/parent',
      data,
    }),

  /**
   * Create child category
   */
  createChild: (data: {
    name: string;
    description?: string;
    imageUrl?: string;
    parentId: number;
    displayOrder?: number;
  }) =>
    request<StandardResponse<Category>>({
      method: 'POST',
      url: '/v1/categories/child',
      data,
    }),
};
