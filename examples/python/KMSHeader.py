# Copyright (c) 2015-2024 Sam Gleske - https://github.com/samrocketman/repository-secrets
# MIT Licensed
import base64
import binascii
import re


class KMSHeader:
    """
    Author:
      Proposal by Sam Gleske
      Copyright (c) 2015-2024 Sam Gleske - https://github.com/samrocketman/repository-secrets
      MIT Licensed

    Proposal:
      For applications where data encrypted at rest is a requirement.  This
      class proposes the concept of a asymmetric KMS header. The encrypted data
      to be symmetrically encrypted and the keys to decrypt are stored by
      encrypting them with an asymmetric public key.  The KMS header would be
      at the beginning symmetrically encrypted data.

    More about the KMS header:
      Generically, a KMS header is an ARN, with the asymmetric algorithm, with
      the asymmetrically encrypted cipher data.  This class is not responsible
      for decryption.  It can return the encrypted data which is part of the
      header intended to be decrypted.

      A KMS header is a KMS ARN, asymmetric algorithm algorithm, and cipher
      text as a contiguous piece of binary data.  When writing encrypted data
      the KMS header gets written first followed by the symmetrically encrypted
      data.

    Developer use case:
      On a front-end system, encrypt data symmetrically and store the
      information necessary to decrypt as KMS header.  The data will be secured
      in any data storage.  The front-end system can only encrypt.  The public
      key can be stored within the application to reduce KMS API calls.  KMS
      need not be used for encryption operations.

      A backend system can use the KMS Header to decrypt with the private key
      using KMS.  Because the main portion of the data is encrypted
      symmetrically, there's a cost savings with reduced KMS API calls
      decrypting small amounts of data.  KMS is not used for

      The first 16 bytes of the KMS header is the KMS key ID.  To determine if
      a key is rotated on all binary blobs you need only inspect the first 16 bytes.

      To determine if a specific AWS account ID is in use you can read the
      first 32 bytes.  The first 16 bytes is the KMS key ID and the second 16
      bytes is the AWS account ID.

    Binary Format of first 36 bytes:
      First 35 bytes (KMS ARN):
        16 bytes = KMS Key ID
        16 bytes = AWS Account ID
        3 bytes = AWS Region

      1 byte algorithm: RSA_2048 (0x01), RSA_3072 (0x02), RSA_4096 (0x03)

    Examles:
      Empty example
        header = KMSHeader()
        header.add_arn("arn:...")
        header.add_algorithm("RSA_...")
        header.add_cipher_data(rsa_encrypted_binary_data)
        header.to_binary()
        header.to_base64()
        len(header) # get current binary header length
      Instantiate a KMS Header.
        header = KMSHeader("arn:...")
        header = KMSHeader("arn:...", algorithm)
        header = KMSHeader(kms_header_binary_data)
        header = KMSHeader.from_base64(kms_header_binary_data_base64_encoded)
      Add encrypted data to KMS Header.
        header.add_cipher_data(rsa_encrypted_binary_data)
      Export a KMS Header.
        header.to_binary()
        header.to_base64()
      Extract information from KMS Header.
        header.get_arn()
        header.get_algorithm()
        header.get_cipher_data()

    TODO
      Add support for header.add_public_key(pem_encoded_rsa_public_key)
      Add support for header.encrypt(plain_text_binary_data)
      Add support for header.decrypt()
    """

    # 3-byte region, 16-byte AWS account ID, 16-byte kms key ID, 512-byte RSA cipher text (4096-bit key), AES cipher data unlimited
    # region = data[:3]
    # account = data[4:20]
    # kms_id = data[20:35]
    # rsa_ciphertext = data[35:548]
    # aes_ciphertext = data[548:] I would use AES-CBC or AES-GCM or ChaCha20-Poly1305
    major_region = {
        "af": "00",
        "ap": "01",
        "ca": "02",
        "eu": "03",
        "il": "04",
        "me": "05",
        "sa": "06",
        "us": "07",
        "us-gov": "08",
    }
    cardinal_endpoint = {
        "north": "00",
        "east": "01",
        "south": "02",
        "west": "03",
        "central": "04",
        "northeast": "05",
        "southeast": "06",
        "southwest": "07",
        "northwest": "08",
    }
    algorithms = {"RSA_2048": "00", "RSA_3072": "01", "RSA_4096": "02"}
    algorithms_byte_size = {"RSA_2048": 256, "RSA_3072": 384, "RSA_4096": 512}

    # binary data which was RSA encrypted
    arn_regex = r"^arn:aws:kms:([^:]+):([^:]+):key/([-0-9a-f]{36})$"

    def __init__(self, arn_or_header=None, algorithm=None):
        """Creates an instance of a KMS header.

        Args:
          arn_or_header: Can be a KMS ARN (str) or binary KMS header.
          algorithm: A supported algorithm KMS would use to decrypt.

        Raises:
          ValueError: If any argument provided is not valid.
        """
        self.add_algorithm(algorithm)
        self.arn = None
        self.cipher_data = None
        if isinstance(arn_or_header, str):
            self.add_arn(arn_or_header)
            return
        if arn_or_header is None:
            self.arn = None
            return
        if not isinstance(arn_or_header, bytes):
            raise ValueError(
                "arn_or_header must be an ARN string or a binary KMS Header."
            )
        data_size = len(arn_or_header)
        if data_size < 35:
            raise ValueError(
                "arn_or_header must be 35-bytes or larger when not type string."
            )
        if data_size >= 36:
            arn_data = binascii.hexlify(arn_or_header[:36]).decode()
        else:
            arn_data = binascii.hexlify(arn_or_header[:35]).decode()
        # assume binary data
        self.arn = self.__hex_to_kms_arn(arn_data[:70])
        if data_size >= 36:
            self.algorithm = self.__get_algorithm(arn_data[70:])
        max_header_bytes = 36 + self.__get_key_bytes()
        if data_size >= max_header_bytes:
            self.cipher_data = arn_or_header[36:max_header_bytes]

    def __len__(self):
        """Get the current size in bytes of the binary KMS Header data.

        KMS Header size can vary:
          0 bytes = User code must provide ARN, algorithm, and cipher data.
          35 bytes = Just ARN; user code must provide algorithm and cipher data.
          36 bytes = ARN with KMS algorithm; user code must provide cipher data.
          292 bytes = ARN with RSA_2048 and encrypted data.
          420 bytes = ARN with RSA_3072 and encrypted data.
          548 bytes = ARN with RSA_4096 and encrypted data.

        Returns:
          36 + number of bytes that get encrypted by RSA key.
        """
        if self.arn is None:
            return 0
        if self.algorithm is None:
            return 35
        if self.cipher_data is None:
            return 36
        return 36 + self.__get_key_bytes()

    @classmethod
    def from_base64(cls, b64_data):
        """Create an instance from base64 encoded data

        Args:
          b64_data: KMS Header binary data which was base64 encoded.

        Returns:
          An instance of KMSHeader.

        Raises:
          ValueError: If decode checks do not pass.
        """
        return cls(base64.b64decode(b64_data))

    def to_binary(self):
        """
        Export the current KMS header as binary data.

        The size of the header will vary.  See __len__ for a detailed
        description of different header sizes.

        Returns:
          Binary KMS header.
        """
        header_data = self.__kms_arn_to_bin(self.arn)
        header_data += self.__algorithm_to_bin(self.algorithm)
        if self.cipher_data:
            header_data += self.cipher_data
        return header_data

    def to_base64(self):
        """
        Export the current KMS header as base64 encoded binary data.

        Returns:
          base64 encoded binary KMS header.
        """
        return base64.b64encode(self.to_binary())

    def get_arn(self):
        """Get the KMS ARN stored in the current KMS header.

        Returns:
          A KMS ARN for an RSA key or None if not defined.
        """
        return self.arn

    def get_algorithm(self):
        """Get the KMS algorithm stored in the current KMS header.

        Returns:
          A KMS algorithm for an RSA key orNone if not defined.
        """
        return self.algorithm

    def add_cipher_data(self, cipher_data):
        """Add RSA encrypted data to KMS Header.

        Args:
          cipher_data: RSA encrypted binary data.

        Raises:
          ValueError: If not exact amount of data required by RSA key size.
        """
        key_size_bytes = self.__get_key_bytes()
        if len(cipher_data) != key_size_bytes:
            raise ValueError(
                "cipher_data was %d bytes but must be exactly %d bytes because algorithm is %s."
                % (len(cipher_data), key_size_bytes, self.algorithm)
            )
        self.cipher_data = cipher_data

    def add_algorithm(self, algorithm=None):
        """
        Add an algorithm to the current KMS header.

        Args:
          algorithm: A supported KMS asymmetric algorithm.

        Raises:
          ValueError: If the algorithm passed is not supported.
        """
        if (algorithm is not None) and (
            not isinstance(algorithm, str)
            or algorithm not in list(self.algorithms.keys())
        ):
            raise ValueError(
                "algorithm must be a string.  Value one of: %s"
                % (", ".join(list(self.algorithms.keys())))
            )
        self.algorithm = algorithm

    def add_arn(self, arn=None):
        """
        Add a KMS ARN to the current KMS header.

        Args:
          arn: An ARN for a KMS key.

        Raises:
          ValueError: If not a proper KMS ARN format.
        """
        if not isinstance(arn, str) or not re.search(self.arn_regex, arn):
            raise ValueError(
                "arn format does not match.  It must match regex: %s" % self.arn_regex
            )
        backup = self.arn
        try:
            self.arn = arn
            self.to_binary()
        except ValueError:
            self.arn = backup
            raise

    def get_cipher_data(self):
        """
        Get data which was encrypted with an RSA public key.

        Returns:
          Binary cipher data or None.
        """
        return self.cipher_data

    def get_partial_kms_header(self, partial_binary_kms_data):
        """Get information about an encrypted blob using a partial KMS header.

        The intent is to gather high level information about the KMS key used
        to encrypt a blob without actually reading all of the encrypted data.
        For example, S3 allows to partially read objects.

        Args:
          partial_binary_kms_data: The first 16, 32, 35, or 36 bytes of a KMS
          header.

        Returns:
          A dictionary with one or more keys: keyid, account, region, and
          algorithm.
        """
        if not isinstance(partial_binary_kms_data, bytes) or (len(partial_binary_kms_data) not in [16, 32, 35, 36]):
            raise ValueError("partial_binary_kms_data is expected to be 16, 32, or 35 bytes.")
        data_size = len(partial_binary_kms_data)
        arn_hex = binascii.hexlify(partial_binary_kms_data).decode()
        kms_information = {
            "keyid": self.__hex_to_keyid(arn_hex[:32])
        }
        if data_size >= 32:
            kms_information["account"] = self.__hex_to_account(arn_hex[32:64])
        if data_size >= 35:
            kms_information["region"] = self.__hex_to_region(arn_hex[64:70])
        if data_size == 36:
            kms_information["algorithm"] = self.__get_algorithm(arn_hex[70:])
        return kms_information

    def __algorithm_to_bin(self, algorithm):
        return binascii.unhexlify(self.algorithms[algorithm])

    def __get_algorithm(self, alg_hex):
        return self.__key_by_value(self.algorithms, alg_hex)

    def __get_key_bytes(self):
        return self.algorithms_byte_size[self.algorithm]

    def __key_by_value(self, dictionary, value):
        return list(dictionary.keys())[list(dictionary.values()).index(value)]

    # last byte is regional integer
    def __regint_to_hex(self, region_int, desired_size=2):
        region_hex = "{0:x}".format(int(region_int))
        buffer = desired_size - len(region_hex)
        if buffer > 0:
            region_hex = ("0" * buffer) + region_hex
        return region_hex

    def __reghex_to_int(self, region_hex):
        return str(int.from_bytes(binascii.unhexlify(region_hex), "big"))

    def __region_to_hex(self, region):
        match = re.search(r"(.*)-([a-z]+)-([0-9]+)", region)
        region_hex = "".join(
            [
                self.major_region[match.group(1)],
                self.cardinal_endpoint[match.group(2)],
                self.__regint_to_hex(match.group(3)),
            ]
        )
        return region_hex

    def __hex_to_region(self, region_hex):
        region = "-".join(
            [
                self.__key_by_value(self.major_region, region_hex[:2]),
                self.__key_by_value(self.cardinal_endpoint, region_hex[2:4]),
                self.__reghex_to_int(region_hex[4:]),
            ]
        )
        return region

    def __keyid_to_hex(self, keyid):
        return keyid.replace("-", "")

    def __hex_to_keyid(self, keyid_hex):
        match = re.search(r"^[0-9a-f]{32}$", keyid_hex)
        if not match:
            raise AssertionError(
                "16-byte Key ID as a hex string was expected but not found (32 chars)."
            )
        keyid = "-".join(
            [
                keyid_hex[:8],
                keyid_hex[8:12],
                keyid_hex[12:16],
                keyid_hex[16:20],
                keyid_hex[20:],
            ]
        )
        return keyid

    def __account_to_hex(self, account):
        account_hex = self.__regint_to_hex(account, 32)
        return account_hex

    def __hex_to_account(self, account_hex):
        return self.__reghex_to_int(account_hex)

    def __kms_arn_to_hex(self, arn):
        match = re.search(self.arn_regex, arn)
        if not match:
            raise ValueError("KMS arn expected.")
        region = match.group(1)
        account = match.group(2)
        keyid = match.group(3)
        try:
            region = self.__region_to_hex(region)
        except KeyError:
            raise ValueError("An invalid region was provided in the arn.")
        try:
            account = self.__account_to_hex(account)
        except ValueError:
            raise ValueError("An invalid account number was provided in the arn.")
        try:
            keyid = self.__keyid_to_hex(keyid)
        except binascii.Error:
            raise ValueError("An invalid keyid was provided in the arn.")

        arn_hex = "".join(
            [
                keyid,
                account,
                region,
            ]
        )
        return arn_hex

    def __hex_to_kms_arn(self, arn_hex):
        match = re.search(r"^[0-9a-f]{70}$", arn_hex)
        if not match:
            raise ValueError("35-byte arn hex expected (70 chars).")
        arn = "arn:aws:kms:%s:%s:key/%s" % (
            self.__hex_to_region(arn_hex[64:]),
            self.__hex_to_account(arn_hex[32:64]),
            self.__hex_to_keyid(arn_hex[:32]),
        )
        return arn

    def __kms_arn_to_bin(self, arn):
        return binascii.unhexlify(self.__kms_arn_to_hex(arn))
