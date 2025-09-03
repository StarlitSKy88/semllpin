import React from 'react';
import { Modal } from 'antd';
import { useUIStore } from '../../stores/uiStore';

interface PrankDetailModalProps {
  modalId: string;
}

const PrankDetailModal: React.FC<PrankDetailModalProps> = ({ modalId }) => {
  const { closeModal } = useUIStore();

  return (
    <Modal
      title="恶搞详情"
      open={true}
      onCancel={() => closeModal(modalId)}
      footer={null}
    >
      <p>恶搞详情功能开发中...</p>
    </Modal>
  );
};

export default PrankDetailModal;