import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { 
  annotationApi, 
  commentApi, 
  lbsApi, 
  walletApi, 
  uploadApi,
  geocodingApi,
  Annotation,
  Comment,
  LBSReward,
  Wallet
} from '../services/api';
import { useAuthStore } from '../stores/auth-store';
import { useMapStore } from '../stores/map-store';
import { useWalletStore } from '../stores/wallet-store';

// 查询键常量
export const queryKeys = {
  annotations: {
    all: ['annotations'] as const,
    map: (bounds?: any) => ['annotations', 'map', bounds] as const,
    nearby: (lat: number, lng: number, radius: number) => ['annotations', 'nearby', lat, lng, radius] as const,
    detail: (id: string) => ['annotations', 'detail', id] as const,
    user: (userId?: string) => ['annotations', 'user', userId] as const,
  },
  comments: {
    all: ['comments'] as const,
    annotation: (annotationId: string, page: number) => ['comments', 'annotation', annotationId, page] as const,
  },
  lbs: {
    all: ['lbs'] as const,
    rewards: (page: number) => ['lbs', 'rewards', page] as const,
  },
  wallet: {
    all: ['wallet'] as const,
    info: ['wallet', 'info'] as const,
    transactions: (page: number) => ['wallet', 'transactions', page] as const,
  },
  geocoding: {
    all: ['geocoding'] as const,
    geocode: (address: string) => ['geocoding', 'geocode', address] as const,
    reverse: (lat: number, lng: number) => ['geocoding', 'reverse', lat, lng] as const,
  },
};

// 标注相关hooks
export const useMapAnnotations = (bounds?: { north: number; south: number; east: number; west: number }) => {
  return useQuery({
    queryKey: queryKeys.annotations.map(bounds),
    queryFn: () => annotationApi.getMapAnnotations(bounds),
    select: (data) => data.data,
    staleTime: 5 * 60 * 1000, // 5分钟
  });
};

export const useNearbyAnnotations = (latitude: number, longitude: number, radius: number = 1000) => {
  return useQuery({
    queryKey: queryKeys.annotations.nearby(latitude, longitude, radius),
    queryFn: () => annotationApi.getNearbyAnnotations(latitude, longitude, radius),
    select: (data) => data.data,
    enabled: !!(latitude && longitude),
    staleTime: 2 * 60 * 1000, // 2分钟
  });
};

export const useAnnotationDetail = (id: string) => {
  return useQuery({
    queryKey: queryKeys.annotations.detail(id),
    queryFn: () => annotationApi.getAnnotation(id),
    select: (data) => data.data,
    enabled: !!id,
  });
};

export const useMyAnnotations = () => {
  const { isAuthenticated } = useAuthStore();
  
  return useQuery({
    queryKey: queryKeys.annotations.user(),
    queryFn: () => annotationApi.getMyAnnotations(),
    select: (data) => data.data,
    enabled: isAuthenticated,
  });
};

// 标注操作mutations
export const useCreateAnnotation = () => {
  const queryClient = useQueryClient();
  const { loadAnnotations } = useMapStore();
  
  return useMutation({
    mutationFn: annotationApi.createAnnotation,
    onSuccess: (data) => {
      // 刷新地图标注
      queryClient.invalidateQueries({ queryKey: queryKeys.annotations.all });
      // 刷新我的标注
      queryClient.invalidateQueries({ queryKey: queryKeys.annotations.user() });
      // 更新地图store
      loadAnnotations();
    },
  });
};

export const useLikeAnnotation = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: annotationApi.likeAnnotation,
    onSuccess: (_, annotationId) => {
      // 刷新标注详情
      queryClient.invalidateQueries({ queryKey: queryKeys.annotations.detail(annotationId) });
      // 刷新地图标注
      queryClient.invalidateQueries({ queryKey: queryKeys.annotations.all });
    },
  });
};

export const useUnlikeAnnotation = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: annotationApi.unlikeAnnotation,
    onSuccess: (_, annotationId) => {
      // 刷新标注详情
      queryClient.invalidateQueries({ queryKey: queryKeys.annotations.detail(annotationId) });
      // 刷新地图标注
      queryClient.invalidateQueries({ queryKey: queryKeys.annotations.all });
    },
  });
};

// 评论相关hooks
export const useAnnotationComments = (annotationId: string, page: number = 1) => {
  return useQuery({
    queryKey: queryKeys.comments.annotation(annotationId, page),
    queryFn: () => commentApi.getAnnotationComments(annotationId, page),
    select: (data) => data.data,
    enabled: !!annotationId,
  });
};

export const useCreateComment = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: commentApi.createComment,
    onSuccess: (_, variables) => {
      // 刷新评论列表
      queryClient.invalidateQueries({ 
        queryKey: queryKeys.comments.annotation(variables.annotationId, 1) 
      });
      // 刷新标注详情（更新评论数量）
      queryClient.invalidateQueries({ 
        queryKey: queryKeys.annotations.detail(variables.annotationId) 
      });
    },
  });
};

// LBS相关hooks
export const useReportLocation = () => {
  const { reportLocation } = useMapStore();
  
  return useMutation({
    mutationFn: ({ latitude, longitude }: { latitude: number; longitude: number }) => 
      lbsApi.reportLocation(latitude, longitude),
    onSuccess: (data, variables) => {
      // 更新地图store中的附近奖励
      reportLocation(variables.latitude, variables.longitude);
    },
  });
};

export const useClaimReward = () => {
  const queryClient = useQueryClient();
  const { claimReward } = useMapStore();
  const { refreshWallet } = useWalletStore();
  
  return useMutation({
    mutationFn: ({ annotationId, latitude, longitude }: { 
      annotationId: string; 
      latitude: number; 
      longitude: number; 
    }) => lbsApi.claimReward(annotationId, latitude, longitude),
    onSuccess: (_, variables) => {
      // 更新地图store
      claimReward(variables.annotationId, variables.latitude, variables.longitude);
      // 刷新钱包信息
      refreshWallet();
      // 刷新LBS奖励记录
      queryClient.invalidateQueries({ queryKey: queryKeys.lbs.all });
    },
  });
};

export const useMyRewards = (page: number = 1) => {
  const { isAuthenticated } = useAuthStore();
  
  return useQuery({
    queryKey: queryKeys.lbs.rewards(page),
    queryFn: () => lbsApi.getMyRewards(page),
    select: (data) => data.data,
    enabled: isAuthenticated,
  });
};

// 钱包相关hooks
export const useWallet = () => {
  const { isAuthenticated } = useAuthStore();
  
  return useQuery({
    queryKey: queryKeys.wallet.info,
    queryFn: () => walletApi.getWallet(),
    select: (data) => data.data,
    enabled: isAuthenticated,
    staleTime: 30 * 1000, // 30秒
  });
};

export const useWalletTransactions = (page: number = 1) => {
  const { isAuthenticated } = useAuthStore();
  
  return useQuery({
    queryKey: queryKeys.wallet.transactions(page),
    queryFn: () => walletApi.getTransactions(page),
    select: (data) => data.data,
    enabled: isAuthenticated,
  });
};

export const useRecharge = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ amount, paymentMethod }: { amount: number; paymentMethod: string }) => 
      walletApi.recharge(amount, paymentMethod),
    onSuccess: () => {
      // 刷新钱包信息
      queryClient.invalidateQueries({ queryKey: queryKeys.wallet.all });
    },
  });
};

export const useWithdraw = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: ({ amount, account }: { amount: number; account: string }) => 
      walletApi.withdraw(amount, account),
    onSuccess: () => {
      // 刷新钱包信息
      queryClient.invalidateQueries({ queryKey: queryKeys.wallet.all });
    },
  });
};

// 文件上传hooks
export const useUploadImage = () => {
  return useMutation({
    mutationFn: uploadApi.uploadImage,
  });
};

export const useUploadImages = () => {
  return useMutation({
    mutationFn: uploadApi.uploadImages,
  });
};

// 地理编码hooks
export const useGeocode = (address: string) => {
  return useQuery({
    queryKey: queryKeys.geocoding.geocode(address),
    queryFn: () => geocodingApi.geocode(address),
    select: (data) => data.data,
    enabled: !!address && address.length > 2,
    staleTime: 10 * 60 * 1000, // 10分钟
  });
};

export const useReverseGeocode = (latitude: number, longitude: number) => {
  return useQuery({
    queryKey: queryKeys.geocoding.reverse(latitude, longitude),
    queryFn: () => geocodingApi.reverseGeocode(latitude, longitude),
    select: (data) => data.data,
    enabled: !!(latitude && longitude),
    staleTime: 10 * 60 * 1000, // 10分钟
  });
};