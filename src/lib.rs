mod decrypt;
mod encrypt;

pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

use cipher::generic_array::{ArrayLength, GenericArray};
use cipher::inout::InOutBuf;
use cipher::{Block, BlockCipher, BlockDecryptMut, BlockEncrypt, BlockSizeUser, TailError, UnalignedBytesDecryptMut};

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}

impl<C: BlockCipher + BlockDecryptMut + BlockEncrypt + BlockSizeUser> UnalignedBytesDecryptMut
for Decryptor<C>
{
    fn proc_tail(
        &self,
        blocks: &mut InOutBuf<Block<Self>>,
        tail: &mut InOutBuf<u8>,
    ) -> Result<(), TailError> {
        match blocks.get_in().last() {
            Some(last) => {
                let mut last: Block<C> = last.clone();
                self.cipher.encrypt_block(&mut last);
                tail.xor_in2out(&last[0..tail.len()]);
                Ok(())
            }
            None => Err(TailError {}),
        }
    }
}
