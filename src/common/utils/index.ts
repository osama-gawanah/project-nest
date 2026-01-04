// Common utility functions
export const paginate = <T>(
  data: T[],
  page: number = 1,
  limit: number = 10,
) => {
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  const paginatedData = data.slice(startIndex, endIndex);

  return {
    data: paginatedData,
    total: data.length,
    page,
    limit,
    totalPages: Math.ceil(data.length / limit),
  };
};

export const generateRandomString = (length: number = 32): string => {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
};

