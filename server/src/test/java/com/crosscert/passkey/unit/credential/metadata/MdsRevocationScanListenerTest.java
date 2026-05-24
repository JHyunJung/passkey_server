package com.crosscert.passkey.unit.credential.metadata;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.crosscert.passkey.credential.metadata.MdsBlobRefreshedEvent;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanListener;
import com.crosscert.passkey.credential.metadata.MdsRevocationScanService;
import com.crosscert.passkey.fido2.mds.MetadataBlob;
import java.lang.reflect.Constructor;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class MdsRevocationScanListenerTest {

  @Mock private MdsRevocationScanService scanService;
  @InjectMocks private MdsRevocationScanListener listener;

  @Test
  void onBlobRefreshed_delegatesToService() throws Exception {
    MetadataBlob blob = newBlob();
    listener.onBlobRefreshed(new MdsBlobRefreshedEvent(blob, Instant.now()));
    verify(scanService, times(1)).scan(blob);
  }

  @Test
  void onBlobRefreshed_swallowsExceptions() throws Exception {
    MetadataBlob blob = newBlob();
    doThrow(new RuntimeException("boom")).when(scanService).scan(any());
    // Must not throw — fail-safe contract.
    listener.onBlobRefreshed(new MdsBlobRefreshedEvent(blob, Instant.now()));
    verify(scanService).scan(blob);
  }

  // MetadataBlob constructor is private; use reflection (same pattern as Task 8 test)
  private static MetadataBlob newBlob() throws Exception {
    Constructor<MetadataBlob> ctor =
        MetadataBlob.class.getDeclaredConstructor(List.class, String.class, Integer.class);
    ctor.setAccessible(true);
    return ctor.newInstance(List.of(), null, null);
  }
}
